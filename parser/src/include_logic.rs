use crate::errors::FileOsError;

use log::debug;

use super::errors::IncludeError;
use program_structure::ast::Include;
use program_structure::report::{Report, ReportCollection};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

pub struct FileStack {
    current_location: Option<PathBuf>,
    black_paths: HashSet<PathBuf>,
    user_inputs: HashSet<PathBuf>,
    libraries: Vec<Library>,
    stack: Vec<PathBuf>,
}

#[derive(Debug)]
struct Library {
    dir: bool,
    path: PathBuf,
}

impl FileStack {
    pub fn new(paths: &[PathBuf], libs: &[PathBuf], reports: &mut ReportCollection) -> FileStack {
        let mut result = FileStack {
            current_location: None,
            black_paths: HashSet::new(),
            user_inputs: HashSet::new(),
            libraries: Vec::new(),
            stack: Vec::new(),
        };
        // add_libraries和add_files都会把文件添加到stack中
        result.add_libraries(libs, reports);
        result.add_files(paths, reports);
        // 这时候处理的文件，全都视作user_inputs
        // 后面还会处理include的文件，这些同样会进入stack，但是不会视作user_inputs
        result.user_inputs = result.stack.iter().cloned().collect::<HashSet<_>>();

        result
    }

    fn add_libraries(&mut self, libs: &[PathBuf], reports: &mut ReportCollection) {
        for path in libs {
            if path.is_dir() {
                self.libraries.push(Library { dir: true, path: path.clone() });
            } else if let Some(extension) = path.extension() {
                // Add Circom files to file stack.
                if extension == "circom" {
                    // 把路径转换为绝对路径
                    match fs::canonicalize(path) {
                        Ok(path) => self.libraries.push(Library { dir: false, path: path.clone() }),
                        Err(_) => {
                            reports.push(
                                FileOsError { path: path.display().to_string() }.into_report(),
                            );
                        }
                    }
                }
            }
        }
    }

    // 递归地添加文件到栈中，其实和add_libraries一样，都是处理文件到stack，只不过处理的对象有区分
    fn add_files(&mut self, paths: &[PathBuf], reports: &mut ReportCollection) {
        for path in paths {
            if path.is_dir() {
                // Handle directories on a best effort basis only.
                if let Ok(entries) = fs::read_dir(path) {
                    let paths: Vec<_> = entries.flatten().map(|x| x.path()).collect();
                    self.add_files(&paths, reports);
                }
            } else if let Some(extension) = path.extension() {
                // Add Circom files to file stack.
                if extension == "circom" {
                    match fs::canonicalize(path) {
                        Ok(path) => self.stack.push(path),
                        Err(_) => {
                            reports.push(
                                FileOsError { path: path.display().to_string() }.into_report(),
                            );
                        }
                    }
                }
            }
        }
    }

    // 解析完一个文件的AST后，可以获得这个文件的include
    // 接着会调用这个方法，把include了的文件也处理掉
    pub fn add_include(&mut self, include: &Include) -> Result<(), Box<Report>> {
        let mut location = self.current_location.clone().expect("parsing file");
        // 把include的路径添加到当前文件的路径后面，拼接出其绝对路径
        location.push(include.path.clone());
        match fs::canonicalize(&location) {
            Ok(path) => {
                if !self.black_paths.contains(&path) {
                    debug!("adding local or absolute include `{}`", location.display());
                    // 加入stack
                    self.stack.push(path);
                    // 注意这里并没有把path添加到black_paths中
                    // 因为加入到black_paths的文件是【解析出AST】的
                    // 所以这里只是加入到stack，当它再次被从stack中捞出并处理完时，才会加入到black_paths
                }
                Ok(())
            }
            // 如果include的路径不是绝对路径，也不是相对路径，那么就尝试从library中找
            Err(_) => self.include_library(include),
        }
    }

    fn include_library(&mut self, include: &Include) -> Result<(), Box<Report>> {
        // try and perform library resolution on the include
        // at this point any absolute path has been handled by the push in add_include
        let pathos = OsString::from(include.path.clone());
        for lib in &self.libraries {
            if lib.dir {
                // 库目录项
                // only match relative paths that do not start with .
                // 只处理相对路径，且不以.开头的（例如 lib.circom 、 dir/lib.circom ）
                if include.path.find('.') == Some(0) {
                    continue;
                }

                // 尝试组合出候选路径，如果存在则加入stack
                let libpath = lib.path.join(&include.path);
                debug!("searching for `{}` in `{}`", include.path, lib.path.display());
                if fs::canonicalize(&libpath).is_ok() {
                    debug!("adding include `{}` from directory", libpath.display());
                    self.stack.push(libpath);
                    return Ok(());
                }
            } else {
                // 库文件项
                // only match include paths with a single component i.e. lib.circom and not dir/lib.circom or
                // ./lib.circom
                if include.path.find(std::path::MAIN_SEPARATOR).is_none() {
                    debug!("checking if `{}` matches `{}`", include.path, lib.path.display());
                    if lib.path.file_name().expect("good library file") == pathos {
                        debug!("adding include `{}` from file", lib.path.display());
                        self.stack.push(lib.path.clone());
                        return Ok(());
                    }
                }
            }
        }

        let error = IncludeError {
            path: include.path.clone(),
            file_id: include.meta.file_id,
            file_location: include.meta.file_location(),
        };
        Err(Box::new(error.into_report()))
    }

    pub fn take_next(&mut self) -> Option<PathBuf> {
        loop {
            match self.stack.pop() {
                None => {
                    break None;
                }
                Some(file_path) if !self.black_paths.contains(&file_path) => {
                    let mut location = file_path.clone();
                    location.pop();
                    // current_location仅在这里设置，在处理include文件时，会依据这个
                    self.current_location = Some(location);
                    // black_paths 会记录已经处理过的文件，避免重复处理
                    self.black_paths.insert(file_path.clone());
                    break Some(file_path);
                }
                _ => {}
            }
        }
    }

    pub fn is_user_input(&self, path: &PathBuf) -> bool {
        self.user_inputs.contains(path)
    }
}
