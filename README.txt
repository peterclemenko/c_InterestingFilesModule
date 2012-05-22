Interesting Files Module
Sleuth Kit Framework C++ Module
May 2012


This module is for the C++ Sleuth Kit Framework.


MODULE DESCRIPTION

This module is a post-processing module that looks for files matching criteria
specified in an input file. The module posts its findings to the blackboard.

MODULE USAGE

Configure the post-processing pipeline to include this module by adding a 
"MODULE" element to the pipeline configuration file. Set the "arguments" 
attribute of the "MODULE" element to pass the path of an input file as a 
module arguments string. A sample input file is provided with the module
source code (interesting_files.xml).



