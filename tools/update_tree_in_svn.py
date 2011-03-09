#!/usr/bin/python

"""
After building can be used to replace documentation,
and jars with the newly built versions in SVN.
"""

import filecmp
import os
import pipes
import sys

FILE = 'f'
DIR = 'd'
NO_EXIST = 'n'

MIME_TYPES_BY_EXTENSION = {
  'html': 'text/html;charset=UTF-8',
  'txt': 'text/plain;charset=UTF-8',
  'css': 'text/css;charset=UTF-8',
  'js': 'text/javascript;charset=UTF-8',
  'jar': 'application/x-java-archive',
  'xsl': 'text/xml;charset=UTF-8',
  'gif': 'image/gif',
  'png': 'image/png'
  }

def sync(src_to_dest):
  """
  Syncrhonize the destination file tree with the source file tree
  in both the current client and in subversion.
  """

  def classify(path):
    if not os.path.exists(path): return NO_EXIST
    if os.path.isdir(path): return DIR
    return FILE

  # If we see a case where (conflict) is present, then we need to be
  # sure to do svn deletes in a separate commit before svn adds.
  conflict = False
  # Keep track of changes to make in subversion
  svn_adds = []
  svn_deletes = []
  svn_propsets = {}

  # A bunch of actions that can be taken to synchronize one aspect
  # of a source file and a destination file
  def run(argv):
    """
    Prints out a command line that needs to be run.
    """
    print ' '.join([pipes.quote(arg) for arg in argv])

  def svn(verb_and_flags, args):
    cmd = ['svn']
    cmd.extend(verb_and_flags)
    cmd.extend(args)
    run(cmd)

  def remove(src, dst): run(['rm', dst])

  def svn_delete(src, dst): svn_deletes.append(dst)

  def recurse(src, dst):
    children = set()
    if os.path.isdir(src): children.update(os.listdir(src))
    if os.path.isdir(dst):
      children.update(os.listdir(dst))
    children.discard('.svn')
    for child in children:
      handle(os.path.join(src, child), os.path.join(dst, child))

  def copy(src, dst): run(['cp', '-f', src, dst])

  def copy_if_different(src, dst):
    if not filecmp.cmp(src, dst, shallow=0): copy(src, dst)

  def svn_add(src, dst):
    svn_adds.append(dst)
    dot = dst.rfind('.')
    if dot >= 0:
      mime_type = MIME_TYPES_BY_EXTENSION.get(dst[dot+1:])
      if mime_type is not None:
        key = ('svn:mime-type', mime_type)
        if key not in svn_propsets:
          svn_propsets[key] = []
        svn_propsets[key].append(dst) 

  def cnf(src, dst): conflict = True

  def mkdir(src, dst): run(['mkdir', dst])

  # The below table contains the actions to take for each possible
  # scenario.
  actions = {
  # src        dst        actions
    (NO_EXIST, NO_EXIST): (),
    (NO_EXIST, FILE)    : (remove, svn_delete,),
    (NO_EXIST, DIR)     : (recurse, remove, svn_delete,),
    (FILE,     NO_EXIST): (copy, svn_add,),
    (FILE,     FILE)    : (copy_if_different,),
    (FILE,     DIR)     : (recurse, remove, svn_delete, copy, svn_add, cnf),
    (DIR,      NO_EXIST): (mkdir, svn_add, recurse,),
    (DIR,      FILE)    : (remove, svn_delete, mkdir, svn_add, recurse, cnf),
    (DIR,      DIR)     : (recurse,),
    }

  # Walk the file tree (see recurse action above) and synchronize it at
  # each step.
  def handle(src, dst):
    src_t = classify(src)
    dst_t = classify(dst)
    for action in actions[(src_t, dst_t)]: action(src, dst)

  for (src, dst) in src_to_dest:
    handle(src, dst)

  if len(svn_deletes):
    svn(['delete'], svn_deletes)
    if conflict: 
      svn(['commit', '-m', 'remove obsolete files from the snapshot tree'],
          commit_args)
  if len(svn_adds):
    svn(['add', '--depth=empty'], svn_adds)
  for ((propname, propvalue), files) in svn_propsets.items():
    svn(['propset', propname, propvalue], files)

if '__main__' == __name__:
  sync([(sys.argv[1], sys.argv[2])])
