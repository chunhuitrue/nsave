use crate::{common::*, configure::*, mmapbuf::*, timeindex::LinkRecord};
use bincode::deserialize_from;
use chrono::{Datelike, Duration, Local, NaiveDateTime, Timelike};
use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    path::PathBuf,
};

#[derive(Debug)]
pub struct SearchTi {
    configure: &'static Configure,
    pub current_date: RefCell<NaiveDateTime>,
    pub end_date: NaiveDateTime,
    dir_id: u64,
    reader: RefCell<Option<MmapBufReader>>,
}

impl SearchTi {
    pub fn new(
        configure: &'static Configure,
        start_date: NaiveDateTime,
        end_date: Option<NaiveDateTime>,
        dir_id: u64,
    ) -> Self {
        let now = Local::now().naive_local();
        let mut e_date = if let Some(time) = end_date { time } else { now };
        if e_date >= now {
            e_date = now - Duration::try_minutes(1).unwrap();
        }

        SearchTi {
            configure,
            current_date: RefCell::new(start_date),
            end_date: e_date,
            dir_id,
            reader: RefCell::new(None),
        }
    }

    fn next_ti_in_dir(&self) -> Option<(LinkRecord, NaiveDateTime)> {
        if self.reader.borrow().is_none() && !self.next_dir() {
            return None;
        }

        let mut binding = self.reader.borrow_mut();
        let reader = binding.as_mut().unwrap();
        if let Ok(ti) = deserialize_from::<_, LinkRecord>(reader) {
            Some((ti, *self.current_date.borrow()))
        } else {
            None
        }
    }

    pub fn next_ti(&self) -> Option<(LinkRecord, NaiveDateTime)> {
        let ti = self.next_ti_in_dir();
        if ti.is_some() {
            return ti;
        }

        if self.next_dir() {
            self.next_ti_in_dir()
        } else {
            None
        }
    }

    fn next_dir(&self) -> bool {
        let mut search_date = *self.current_date.borrow();
        while search_date <= self.end_date {
            if let Ok((ti_file, _ti_file_path)) =
                date2ti_file(self.configure, search_date, self.dir_id)
            {
                *self.current_date.borrow_mut() = search_date;
                *self.reader.borrow_mut() = Some(MmapBufReader::new(ti_file));
                return true;
            }
            search_date += Duration::try_minutes(1).unwrap();
        }
        false
    }
}

pub fn date2ti_file(
    configure: &'static Configure,
    date: NaiveDateTime,
    dir: u64,
) -> Result<(File, PathBuf), StoreError> {
    let mut path = PathBuf::new();
    path.push(configure.main.store_path.clone());
    path.push(format!("{dir:03}"));
    path.push(format!("{:04}", date.year()));
    path.push(format!("{:02}", date.month()));
    path.push(format!("{:02}", date.day()));
    path.push(format!("{:02}", date.hour()));
    path.push(format!("{:02}", date.minute()));
    path.push("timeindex.ti");

    match OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .truncate(false)
        .open(&path)
    {
        Ok(file) => Ok((file, path)),
        Err(e) => Err(StoreError::CliError(format!("open file error: {e}"))),
    }
}
