/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file InterestingFilesModule.cpp
 * Contains the implementation of a post-processing/reporting module that
 * looks for files matching interesting file set criteria specified in a 
 * module configuration file. The module posts its findings to the blackboard. 
 */

// System includes
#include <string>
#include <vector>
#include <set>
#include <sstream>
#include <fstream>

// Framework includes
#include "TskModuleDev.h"
#include "framework.h"

// Poco includes
#include "Poco/AutoPtr.h"
#include "Poco/Path.h"
#include "Poco/File.h"
#include "Poco/DOM/DOMParser.h"
#include "Poco/DOM/Document.h"
#include "Poco/DOM/NodeList.h"
#include "Poco/DOM/NamedNodeMap.h"
#include "Poco/SAX/InputSource.h"
#include "Poco/SAX/SAXException.h"

namespace
{
    // An interesting files set is defined by a set name, a set description, and one or more SQL WHERE clauses
    // that specify what files belong to the set. 
    struct InterestingFilesSet
    {
        InterestingFilesSet() : name(""), description("") {}
        std::string name;
        std::string description;
        vector<std::string> conditions;
    };

    // Interesting file set definitions are read from a configuration file in the initialize() module API 
    // and the file queries are executed in the report() module API. The following vector stores the search objects between 
    // calls to intitialize() and report(). 
    std::vector<InterestingFilesSet> fileSets;

    // A helper function used to add escape '_' and '%' characters in a SQL LIKE pattern with '#' characters.
    std::string addEscapesToPattern(const std::string &inputPattern) 
    {
        std::string outputPattern;

        for (size_t i = 0; i < inputPattern.length(); ++i) 
        {
            char c = inputPattern[i];
            if (c == '_' || c == '%' || c == '#')
            {
                outputPattern += '#';
            }
            outputPattern += c;
        } 

        return outputPattern;
    }

    // A helper function used to add optional file type (file, directory) and path substring filters to an SQL WHERE 
    // clause for a file search condition.
    void addPathAndTypeFilterOptions(const Poco::XML::Node *conditionDefinition, std::stringstream &conditionBuilder)
    {
        if (conditionDefinition->hasAttributes())
        {
            // Look for pathFilter and typeFilter attributes. The presence of an attributes other than pathFilter or typeFilter is logged
            // as an error, but is not treated as a fatal error. Likewise, an attribute with an empty value is an error, but not a
            // fatal error.
            Poco::AutoPtr<Poco::XML::NamedNodeMap> attributes = conditionDefinition->attributes(); 
            for (unsigned long i = 0; i < attributes->length(); ++i)
            {
                Poco::XML::Node *attribute = attributes->item(i);
                const std::string& attributeName = Poco::XML::fromXMLString(attribute->nodeName());
                const std::string &attributeValue = Poco::XML::fromXMLString(attribute->nodeValue());
                if (!attributeValue.empty())
                {
                    if (attributeName == "pathFilter")
                    {        
                        // File must include a specified substring in its path.
                        conditionBuilder << " AND UPPER(full_path) LIKE UPPER('%" + addEscapesToPattern(attributeValue) + "%') ESCAPE '#'";
                    }
                    else if (attributeName == "typeFilter")
                    {
                        if (attributeValue == "file")
                        {
                            // File must be a regular file.
                            conditionBuilder << " AND meta_type = " << TSK_FS_META_TYPE_REG;
                        }
                        else if (attributeValue == "dir")
                        {
                            // File must be a directory.
                            conditionBuilder << " AND meta_type = " << TSK_FS_META_TYPE_DIR;
                        }
                        else
                        {
                            std::stringstream msg;
                            msg << "InterestingFilesModule::addPathAndTypeFilterOptions : ignored unrecognized '" << attributeValue << "' value of typefilter attribute of '" << Poco::XML::fromXMLString(conditionDefinition->nodeName()) << "' element"; 
                            LOGERROR(msg.str());
                        }
                    }
                    else
                    {
                        std::stringstream msg;
                        msg << "InterestingFilesModule::addPathAndTypeFilterOptions : ignored unrecognized '" << attributeName << "' attribute of '" << Poco::XML::fromXMLString(conditionDefinition->nodeName()) << "' element"; 
                        LOGERROR(msg.str());
                    }
                }
                else
                {
                    std::stringstream msg;
                    msg << "InterestingFilesModule::addPathAndTypeFilterOptions : ignored '" << attributeName << "' attribute without a value in '" << Poco::XML::fromXMLString(conditionDefinition->nodeName()) << "' element" ; 
                    LOGERROR(msg.str());
                }
            }
        }
    }

    // A helper function used to create an SQL WHERE clause for a file query based on file name.
    void compileNameSearchCondition(const Poco::XML::Node *conditionDefinition, std::vector<std::string> &conditions)
    {
        std::string name = Poco::XML::fromXMLString(conditionDefinition->innerText());
        if (!name.empty())
        {
            std::stringstream conditionBuilder;
            conditionBuilder << "WHERE UPPER(name) = UPPER(" +  TskServices::Instance().getImgDB().quote(name) + ")";
            addPathAndTypeFilterOptions(conditionDefinition, conditionBuilder);
            conditionBuilder << " ORDER BY file_id";
            conditions.push_back(conditionBuilder.str());
        }
    }

    // A helper function used to create an SQL WHERE clause for a file query based on file extension.
    void compileExtensionSearchCondition(const Poco::XML::Node *conditionDefinition, std::vector<std::string> &conditions)
    {
        std::string extension = Poco::XML::fromXMLString(conditionDefinition->innerText());
        if (!extension.empty())
        {
            // Supply the leading dot, if omitted.
            if (extension[0] != '.')
            {
                extension.insert(0, ".");
            }

            std::stringstream conditionBuilder;
            conditionBuilder << "WHERE UPPER(name) LIKE UPPER('%" << addEscapesToPattern(extension) << "') ESCAPE '#' ";
            addPathAndTypeFilterOptions(conditionDefinition, conditionBuilder);            
            conditionBuilder << " ORDER BY file_id";
            conditions.push_back(conditionBuilder.str());
        }
    }

    // A helper function to ensure that set names will be able to be used as folder names, if desired.
    bool isValidSetName(const std::string &setName)
    {
        // The set name cannot contain a path character since it may be used later
        // as a folder name by a save interesting files module.
        if (setName.find_first_of("<>:\"/\\|?*") != std::string::npos)
        {
            std::stringstream msg;
            msg << "InterestingFilesModule::isValidSetName : INTERESTING_FILE_SET 'name' attribute value '" << setName << "' contains file path character";
            LOGERROR(msg.str());
            return false;
        }

        // The set name cannot be shorthand for the a current directory or parent directory since
        // as a folder name by a save interesting files module.
        if (setName == (".") || setName == (".."))
        {
            std::stringstream msg;
            msg << "InterestingFilesModule::isValidSetName : INTERESTING_FILE_SET 'name' attribute value '" << setName << "' is directory alias";
            LOGERROR(msg.str());
            return false;
        }

        // Every set must be uniquely named.
        static std::set<std::string> setNames;
        if (setNames.count(setName) != 0)
        {
            std::stringstream msg;
            msg << "InterestingFilesModule::isValidSetName : discarded duplicate INTERESTING_FILE_SET name definition '" << setName << "'";
            LOGERROR(msg.str());
            return false;
        }
        setNames.insert(setName);

        return true;
    }

    // A helper function to turn an interesting files set definition into an InterestingFilesSet object.
    void compileInterestingFilesSet(const Poco::XML::Node *fileSetDefinition)
    {
        // Create a counter for use in generating default interesting file set names.
        static unsigned long defaultSetNumber = 1;

        // Determine the name and description of the file set.
        InterestingFilesSet fileSet;
        if (fileSetDefinition->hasAttributes())
        {
            Poco::AutoPtr<Poco::XML::NamedNodeMap> attributes = fileSetDefinition->attributes(); 
            for (unsigned long i = 0; i < attributes->length(); ++i)
            {
                Poco::XML::Node *attribute = attributes->item(i);
                const std::string &attributeName = Poco::XML::fromXMLString(attribute->nodeName());                
                const std::string &attributeValue = Poco::XML::fromXMLString(attribute->nodeValue());
                if (!attributeValue.empty())
                {
                    if (attributeName == "name")
                    {        
                        fileSet.name = attributeValue;
                    }
                    else if (attributeName == "description")
                    {
                        fileSet.description = attributeValue;
                    }
                    else
                    {
                        std::stringstream msg;
                        msg << "InterestingFilesModule::compileInterestingFilesSet : ignored unrecognized INTERESTING_FILE_SET attribute '" << attributeName << "'"; 
                        LOGERROR(msg.str());
                    }
                }
                else
                {
                    std::stringstream msg;
                    msg << "InterestingFilesModule::compileInterestingFilesSet : ignored INTERESTING_FILE_SET '" << attributeName << "' attribute without a value"; 
                    LOGERROR(msg.str());
                }
            }
        }

        // Every search must be named (the description is optional).
        if (fileSet.name.empty())
        {
            // Supply a default name.
            std::stringstream nameBuilder;
            nameBuilder << "Unnamed_" << defaultSetNumber++;
            fileSet.name = nameBuilder.str();
        }

        if (isValidSetName(fileSet.name))
        {
            // Add the search conditions.
            Poco::AutoPtr<Poco::XML::NodeList>conditionDefinitions = fileSetDefinition->childNodes();
            for (unsigned long i = 0; i < conditionDefinitions->length(); ++i)
            {
                Poco::XML::Node *conditionDefinition = conditionDefinitions->item(i);
                if (conditionDefinition->nodeType() == Poco::XML::Node::ELEMENT_NODE) 
                {
                    const std::string &conditionType = Poco::XML::fromXMLString(conditionDefinition->nodeName());
                    if (conditionType == "NAME")
                    {
                        compileNameSearchCondition(conditionDefinition, fileSet.conditions);
                    }
                    else if (conditionType == "EXTENSION")
                    {
                        compileExtensionSearchCondition(conditionDefinition, fileSet.conditions);
                    }
                    else
                    {
                        std::stringstream msg;
                        msg << "InterestingFilesModulecompileInterestingFilesSet : ignored unrecognized INTERESTING_FILE_SET child element '" << conditionType << "'"; 
                        LOGERROR(msg.str());
                    }
                }
            }

            // Save the search to execute when report() is called.
            if (!fileSet.conditions.empty())
            {
                fileSets.push_back(fileSet);
            }
            else
            {
                std::stringstream msg;
                msg << "InterestingFilesModulecompileInterestingFilesSet : ignored empty INTERESTING_FILE_SET element '" << fileSet.name << "'"; 
                LOGERROR(msg.str());
            }
        }
    }
}

extern "C" 
{
    /**
     * Module identification function. 
     *
     * @return The name of the module.
     */
    TSK_MODULE_EXPORT const char *name()
    {
        return "InterestingFilesModule";
    }

    /**
     * Module identification function. 
     *
     * @return A description of the module.
     */
    TSK_MODULE_EXPORT const char *description()
    {
        return "Looks for files matching criteria specified in a module configuration file";
    }

    /**
     * Module identification function. 
     *
     * @return The version of the module.
     */
    TSK_MODULE_EXPORT const char *version()
    {
        return "0.0.0";
    }

    /**
    * Module initialization function. The initialization arguments string should
    * provide the path of a module configuration file that defines what files 
    * are interesting. If the empty string is passed to this function, the module
    * assumes a default config file is present in the output directory.
    *
    * @param args Path of the configuration file that defines what files are 
    * interesting, may be set to the empty string.
    * @return Always returns TskModule::OK since it is a post-processing module. 
    */
    TSK_MODULE_EXPORT TskModule::Status initialize(const char* arguments)
    {
        // Make sure the file sets are cleared in case initialize() is called more than once.
        fileSets.clear();

        std::string configFilePath;
        if (arguments != NULL)
        {
            configFilePath = arguments;
        }

        if (configFilePath.empty())
        {
            // Assume use of default config file.
            std::stringstream pathBuilder;
            pathBuilder << GetSystemProperty(TskSystemProperties::MODULE_DIR) << Poco::Path::separator() << "InterestingFilesModule" << Poco::Path::separator() << "interesting_files.xml";
            configFilePath = pathBuilder.str();
        }

        // Log the config file path for reference in case of error.
        std::stringstream msg;
        msg << "InterestingFilesModule::initialize : configured with config file path '" << configFilePath << "'";
        LOGINFO(msg.str());

        // Open the config file.
        Poco::File configFile = Poco::File(configFilePath);
        if (configFile.exists())
        {
            std::ifstream configStream(configFile.path().c_str());
            if (configStream)
            {
                try 
                {
                    // Parse the config file.
                    Poco::AutoPtr<Poco::XML::Document> configDoc = Poco::XML::DOMParser().parse(&Poco::XML::InputSource(configStream));

                    // Compile the interesting file sets specified in the the config file into InterestingFilesSet objects.
                    Poco::AutoPtr<Poco::XML::NodeList> fileSetDefinitions = configDoc->getElementsByTagName("INTERESTING_FILE_SET");
                    for (unsigned long i = 0; i < fileSetDefinitions->length(); ++i) 
                    {
                        compileInterestingFilesSet(fileSetDefinitions->item(i));
                    }
                }
                catch (Poco::XML::SAXParseException &ex) 
                {
                    std::stringstream msg;
                    msg << "InterestingFilesModule::initialize : exception parsing config file '" << configFilePath << "' : " << ex.displayText();
                    LOGERROR(msg.str());
                }  
            }
            else
            {
                std::stringstream msg;
                msg << "InterestingFilesModule::initialize : failed to open config file '" << configFilePath << "'";
                LOGERROR(msg.str());
            }
        }
        else
        {
            std::stringstream msg;
            msg << "InterestingFilesModule::initialize : could not find config file'" << configFilePath << "'";
            LOGERROR(msg.str());
        }

        // Always return OK when initializing a reporting/post-processing pipeline module so the pipeline is not disabled by the presence of a non-functional module.
        return TskModule::OK;
    }

    /**
     * Module execution function. Looks for files matching the criteria specified in the 
     * configuration file and posts its findings to the blackboard.
     *
     * @returns Returns TskModule::FAIL if an error occurs, TskModule::OK otherwise.
     */
    TSK_MODULE_EXPORT TskModule::Status report()
    {
        if (fileSets.empty())
        {
            LOGERROR("InterestingFilesModule::report : no valid interesting file set definitions");
            return TskModule::FAIL;
        }

        TskModule::Status returnCode = TskModule::OK;
        for (std::vector<InterestingFilesSet>::iterator fileSet = fileSets.begin(); fileSet != fileSets.end(); ++fileSet)
        {
            for (std::vector<string>::iterator condition = (*fileSet).conditions.begin(); condition != (*fileSet).conditions.end(); ++condition)
            {
                try
                {
                    vector<uint64_t> fileIds = TskServices::Instance().getImgDB().getFileIds(*condition);
                    for (size_t i = 0; i < fileIds.size(); i++)
                    {
                        TskBlackboardArtifact artifact = TskServices::Instance().getBlackboard().createArtifact(fileIds[i], TSK_INTERESTING_FILE_HIT);
                        TskBlackboardAttribute attribute(TSK_SET_NAME, "InterestingFiles", (*fileSet).description, (*fileSet).name);
                        artifact.addAttribute(attribute);
                    }
                }
                catch (TskException &ex)
                {
                    // Log the error and try the next file set, but signal that an error occurred with a FAIL return code.
                    std::stringstream msg;
                    msg << "InterestingFilesModule::report : exception searching for file set hits for condition '" << *condition << "' : " << ex.message();
                    LOGERROR(msg.str());
                    returnCode = TskModule::FAIL;
                }
            }
        }

        return returnCode;
    }

    /**
     * Module cleanup function. Disposes of file search data created during initialization.
     *
     * @returns TskModule::OK
     */
    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
        fileSets.clear();
        return TskModule::OK;
    }
}
