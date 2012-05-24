Interesting Files Module
Sleuth Kit Framework C++ Module
May 2012


This module is for the C++ Sleuth Kit Framework.


DESCRIPTION

This module is a post-processing module that looks for files 
matching criteria specified in a module configuration file. 
The criteria can specify the file or directory's name, extension,
or path.  This module is useful for identify all files of a given
type (based on extension) or ceratin names. 


USAGE

Add this module to a post-processing/reporting pipeline.  See the TSK 
Framework documents for information on adding the module 
to the pipeline:

    http://www.sleuthkit.org/sleuthkit/docs/framework-docs/

The module takes the path to the configuration file as an argument. 
The configuration file is XML and defines the rules to search for. 

The schema has the following elements that define the search. Searches
are done case insensitive.
* EXTENSION: Search the end of file names for this string.  The "." is
optional, but if you do not provide it then a the string "jpg" will match
the file "ajpg". 
* NAME: Search the file names for a file or directory that matches this
string. It must be an exact length, case insensitive match. For example, 
the string "bomb" will not match "abomb". 

The DESCRIPTION element can be defined for each search criteria and its
intended use is to describe why the search is important.  It could let
the end user know what next step to take if this search is successful.


RESULTS

The result of the lookup is written to an attribute in the blackboard. 
You can use the SaveInterestingFiles module to save the identified 
files to a local directory. 




