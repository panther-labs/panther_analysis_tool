import tqdm

# Pre-create tqdm's multiprocessing lock before any test runs.
#
# sqlfluff.parse() uses tqdm for a progress bar. tqdm's __new__ always calls
# get_lock(), which on first call creates a TqdmDefaultWriteLock containing a
# multiprocessing.RLock(). Creating that RLock triggers Python's
# multiprocessing resource_tracker to start via os.pipe().
#
# pyfakefs patches os.pipe. If the first sqlfluff.parse() call happens inside
# a pyfakefs-active test, the resource_tracker's communication pipe is created
# through the fake os.pipe, giving the tracker an invalid FD. At process exit
# the tracker subprocess fails with:
#   OSError: [Errno 9] Bad file descriptor
#
# Calling get_lock() here — before any test setUp — ensures the
# multiprocessing lock (and therefore the resource_tracker pipe) is created
# against the real OS, not pyfakefs.
#
# Running unit tests without this causes the tests to hang indefinitely when run
# inside a normal terminal but not inside CI jobs and AI coding sessions.
tqdm.tqdm.get_lock()
