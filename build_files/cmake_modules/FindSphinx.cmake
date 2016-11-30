# This module tries to find Sphinx executable that is used for generating
# documentation
#
# SPHINX_EXECUTABLE, sphinx-build executable

find_program(SPHINX_EXECUTABLE NAMES sphinx-build
  HINTS
  $ENV{SPHINX_DIR}
  PATH_SUFFIXES bin
  DOC "Sphinx documentation generator"
)
 
include(FindPackageHandleStandardArgs)
 
find_package_handle_standard_args(Sphinx DEFAULT_MSG
  SPHINX_EXECUTABLE
)
 
mark_as_advanced(
  SPHINX_EXECUTABLE
)