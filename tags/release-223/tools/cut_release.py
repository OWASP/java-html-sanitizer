#!/usr/bin/python

"""
Packages a new maven release.
"""

import os
import re
import shutil
import subprocess
import sys
import xml.dom.minidom

def mime_type_from_path(path):
  if path.endswith(".pom"):
    return "text/xml;charset=UTF-8"
  elif path.endswith(".jar"):
    return "application/java-archive"
  return None

if "__main__" == __name__:
  # Compute directories relative to tools.
  trunk_directory_path = os.path.realpath(os.path.join(
    os.path.dirname(sys.argv[0]),
    ".."))
  maven_directory_path = os.path.realpath(os.path.join(
    os.path.dirname(sys.argv[0]),
    "..",
    "..",
    "maven",
    "owasp-java-html-sanitizer",
    "owasp-java-html-sanitizer"))
  maven_metadata_path = os.path.join(
    maven_directory_path,
    "maven-metadata.xml")
  version_template_directory_path = os.path.join(
    maven_directory_path,
    "+++version+++")
  jar_path = os.path.join(
    trunk_directory_path,
    "distrib",
    "lib",
    "owasp-java-html-sanitizer.jar")
  src_jar_path = os.path.join(
    trunk_directory_path,
    "distrib",
    "lib",
    "owasp-java-html-sanitizer-sources.jar")
  doc_jar_path = os.path.join(
    trunk_directory_path,
    "distrib",
    "lib",
    "owasp-java-html-sanitizer-javadoc.jar")

  # Make sure the directory_structures we expect exist.
  assert os.path.isdir(maven_directory_path), maven_directory_path
  assert os.path.isdir(trunk_directory_path), trunk_directory_path
  assert os.path.isfile(maven_metadata_path), maven_metadata_path
  assert os.path.isdir(version_template_directory_path), (
         version_template_directory_path)
  assert os.path.isfile(jar_path), jar_path
  assert os.path.isfile(src_jar_path), src_jar_path
  assert os.path.isfile(doc_jar_path), doc_jar_path

  # Get svn info of the trunk directory.
  svn_info_xml = (
     subprocess.Popen(["svn", "info", "--xml", trunk_directory_path],
                      stdout=subprocess.PIPE)
    .communicate()[0])
  svn_info = xml.dom.minidom.parseString(svn_info_xml)

  # Process SVN output XML to find fields.
  date_element = svn_info.getElementsByTagName("date")[0]
  entry_element = svn_info.getElementsByTagName("entry")[0]
  def inner_text(node):
    if node.nodeType == 3: return node.nodeValue
    if node.nodeType == 1:
      return "".join([inner_text(child) for child in node.childNodes])
    return ""

  # Create a list of fields to use in substitution.
  fields = {
    "version": "r%s" % entry_element.getAttribute("revision"),
    "timestamp": re.sub(r"[^.\d]|\.\d+", "", inner_text(date_element))
  }

  def replace_fields(s):
    return re.sub(r"\+\+\+(\w+)\+\+\+", lambda m: fields[m.group(1)], s)

  # List of files that need to have ##DUPE## and ##REPLACE## sections expanded
  # NOTE(12 February 2013): We no longer rewrite maven_metadata_path since this
  # project is now hosted in Maven Central, and maven_metadata used a
  # groupId/artifactId pair that is incompatible with the convention used by
  # Maven Central.
  # All maven versions after 12 February are undiscoverable by looking at
  # maven_metadata.
  files_to_rewrite = []
  new_file_paths = []

  def copy_directory_structure_template(src_path, container_path):
    dest_path = os.path.join(
      container_path,
      replace_fields(os.path.basename(src_path)))
    if os.path.isdir(src_path):
      os.mkdir(dest_path)
      for child in os.listdir(src_path):
        # Skip .svn directories.
        if "." == child[0:1]: continue
        copy_directory_structure_template(
          os.path.join(src_path, child), dest_path)
    else:
      shutil.copyfile(src_path, dest_path)
      mime_type = mime_type_from_path(dest_path)
      if mime_type is None or mime_type.startswith("text/"):
        files_to_rewrite.append(dest_path)
      new_file_paths.append(dest_path)
    return dest_path

  def rewrite_file(path):
    lines = []
    in_file = open(path, "r")
    try:
      file_content = in_file.read()
    finally:
      in_file.close()
    for line in file_content.split("\n"):
      indentation = re.match(r"^\s*", line).group()
      matches = re.findall(r"(<!--##REPLACE##(.*)##END##-->)", line)
      if len(matches) >= 2: raise Error("%s: %s" % (path, line))
      if len(matches):
        match = matches[0]
        line = "%s%s %s" % (indentation, replace_fields(match[1]), match[0])
      else:
        matches = re.findall("##DUPE##(.*)##END##", line)
        if len(matches) >= 2: raise Error("%s: %s" % (path, line))
        if len(matches):
          match = matches[0]
          lines.append("%s%s" % (indentation, replace_fields(match)))
      lines.append(line)
    out_file = open(path, "w")
    try:
      out_file.write("\n".join(lines))
    finally:
      out_file.close()

  versioned_jar_path = os.path.join(
    version_template_directory_path,
    "owasp-java-html-sanitizer-+++version+++.jar")
  versioned_src_jar_path = os.path.join(
    version_template_directory_path,
    "owasp-java-html-sanitizer-+++version+++-sources.jar")
  versioned_doc_jar_path = os.path.join(
    version_template_directory_path,
    "owasp-java-html-sanitizer-+++version+++-javadoc.jar")

  shutil.copyfile(jar_path, versioned_jar_path)
  shutil.copyfile(src_jar_path, versioned_src_jar_path)
  shutil.copyfile(doc_jar_path, versioned_doc_jar_path)
  ok = False
  version_directory_path = None
  try:
    version_directory_path = copy_directory_structure_template(
      version_template_directory_path, maven_directory_path)
    for file_to_rewrite in files_to_rewrite:
      rewrite_file(file_to_rewrite)
    ok = True
  finally:
    os.unlink(versioned_jar_path)
    os.unlink(versioned_src_jar_path)
    os.unlink(versioned_doc_jar_path)
    if not ok and version_directory_path is not None:
      shutil.rmtree(version_directory_path)

  print "svn add '%s'" % version_directory_path

  for new_file_path in new_file_paths:
    mime_type = mime_type_from_path(new_file_path)
    if mime_type is not None:
      print "svn propset svn:mime-type '%s' '%s'" % (mime_type, new_file_path)
