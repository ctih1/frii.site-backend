import fcntl, os

def lock_file(f):
  if f.writable():
    fcntl.lockf(f, fcntl.LOCK_EX)

def unlock_file(f):
  if f.writable():
    fcntl.lockf(f, fcntl.LOCK_UN)