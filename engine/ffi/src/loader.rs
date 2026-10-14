//! The bundle loader thread: every `strata_engine_map` of a process runs
//! on one long-lived thread.
//!
//! Why (W09-Q-02 soak, 14/10/2026): NGINX maps bundles on its thread pool
//! (32 threads by default). glibc gives every thread its own malloc arena,
//! and mapping the full signature package allocates and frees tens of MB
//! there. Each arena keeps that memory after the engine is dropped
//! (`malloc_trim` does not give it back), so a worker grew by about 18 MB
//! each time a full bundle landed on a thread pool thread that had not
//! mapped one before: 8 -> 147 MB in 24 hours. On one thread, the same
//! arena is reused and the memory stays flat.
//!
//! The thread belongs to the process that made it: after `fork` (NGINX
//! master -> workers) the child makes its own. It blocks every signal, so
//! a thread made in the NGINX master before it blocks its signals never
//! takes the master's SIGHUP or SIGTERM. If the thread cannot be made, the
//! job runs on the caller's thread, as before.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;
use std::sync::mpsc::{self, Sender};

type Job = Box<dyn FnOnce() + Send>;

/// The loader of this process: its pid and the way to it.
static LOADER: Mutex<Option<(u32, Sender<Job>)>> = Mutex::new(None);

fn spawn() -> Option<Sender<Job>> {
    let (tx, rx) = mpsc::channel::<Job>();
    std::thread::Builder::new()
        .name("strata-loader".into())
        .spawn(move || {
            block_signals();
            // ends when the process's sender is dropped
            for job in rx {
                // a panicking job drops its result sender: the caller sees it
                let _ = catch_unwind(AssertUnwindSafe(job));
            }
        })
        .ok()?;
    Some(tx)
}

fn block_signals() {
    // SAFETY: sigfillset initializes the set; pthread_sigmask only changes
    // this thread's mask.
    unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        libc::pthread_sigmask(libc::SIG_BLOCK, &all, std::ptr::null_mut());
    }
}

/// Runs `f` on the loader thread and returns its result; None when `f`
/// panicked.
pub fn run<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    let job: Job = Box::new(move || {
        let _ = tx.send(f());
    });
    let not_sent = {
        let mut g = LOADER.lock().unwrap_or_else(|e| e.into_inner());
        let pid = std::process::id();
        if g.as_ref()
            .is_none_or(|(p, s)| *p != pid || s.send(Box::new(|| {})).is_err())
        {
            *g = spawn().map(|s| (pid, s));
        }
        match g.as_ref() {
            Some((_, s)) => s.send(job).err().map(|e| e.0),
            None => Some(job),
        }
    };
    if let Some(job) = not_sent {
        // no loader thread: here, as before
        let _ = catch_unwind(AssertUnwindSafe(job));
    }
    rx.recv().ok()
}

/// The loader thread's id, for tests.
pub fn thread_id() -> Option<std::thread::ThreadId> {
    run(|| std::thread::current().id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_caller_runs_on_the_same_thread() {
        let first = thread_id().unwrap();
        assert_ne!(first, std::thread::current().id());
        let others: Vec<_> = (0..8)
            .map(|_| std::thread::spawn(thread_id))
            .map(|h| h.join().unwrap().unwrap())
            .collect();
        assert!(others.iter().all(|t| *t == first), "{others:?}");
    }

    #[test]
    fn a_panic_is_reported_and_the_loader_survives() {
        assert_eq!(run(|| -> u32 { panic!("bad bundle") }), None);
        assert_eq!(run(|| 7), Some(7));
    }

    #[test]
    fn signals_are_blocked_on_the_loader() {
        let blocked = run(|| {
            // SAFETY: reads this thread's mask into a zeroed set.
            unsafe {
                let mut cur: libc::sigset_t = std::mem::zeroed();
                libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut cur);
                libc::sigismember(&cur, libc::SIGHUP) == 1
                    && libc::sigismember(&cur, libc::SIGTERM) == 1
            }
        });
        assert_eq!(blocked, Some(true));
    }
}
