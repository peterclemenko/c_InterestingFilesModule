/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file InterestingFiles.cpp
 * This module is a post-processing module that looks for files matching criteria
 * specified in an input file. The module posts its findings to the blackboard.
 */

// System includes
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
#include "Poco/SAX/InputSource.h"
#include "Poco/SAX/SAXException.h"

static const char *defaultInputFilename = "interesting_files.xml";
static string inputFilePath;

static std::string escapeWildcard(const std::string &s, char escChar) {
    std::string newS;
    for (size_t i = 0; i < s.length(); i++) {
        char c = s[i];
        if (c == '_' || c == '%' || c == escChar) {
            newS += escChar;
        }
        newS += c;
    }
    return newS;
}

static void addInterestingFilesToBlackboard(string & condition, string & description)
{
    vector<uint64_t> fileIds = TskServices::Instance().getImgDB().getFileIds(condition);
    TskBlackboard &bb = TskServices::Instance().getBlackboard();
    for (size_t i = 0; i < fileIds.size(); i++) {
        bb.createGenInfoAttribute(fileIds[i], TskBlackboardAttribute(TSK_INTERESTING_FILE, "InterestingFiles", description, 0));
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
        return "InterestingFiles";
    }

    /**
     * Module identification function. 
     *
     * @return A description of the module.
     */
    TSK_MODULE_EXPORT const char *description()
    {
        return "";
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
     * provide the path of an input file that defines what files are interesting.
     *
     * @param args Path of the input file that defines what files are interesting.
     * @return TskModule::OK if initialization succeeded, otherwise TskModule::FAIL.
     */
    TskModule::Status TSK_MODULE_EXPORT initialize(const char*  arguments)
    {
        std::string args(arguments);

        if (!args.empty()) {
            std::wstringstream msg;
            msg << L"InterestingFiles: Initialized with argument: " << TskUtilities::toUTF16(args);
            LOGINFO(msg.str().c_str());
            inputFilePath = args;
        }
        return TskModule::OK;
    }
    
    /**
     * Module execution function. Looks for files matching criteria specified in an 
     * input file and posts its findings to the blackboard.
     *
     * @returns Returns TskModule::FAIL if an error occurs, TskModule::OK otherwise.
     */
    TskModule::Status TSK_MODULE_EXPORT report()
    {
        LOGINFO(L"InterestingFiles - search started.");
        if (!inputFilePath.length()) {
            // Path not provided via args, look for the interesting files config file in the output directory.
            inputFilePath = TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskSystemProperties::OUT_DIR));
            inputFilePath.append("\\");
            inputFilePath.append(defaultInputFilename);
        }
        Poco::File file = Poco::File(inputFilePath);
        std::ifstream in(file.path().c_str());

        if (in) {
            // Parse the xml file
            try {
                Poco::XML::InputSource src(in);
                Poco::XML::DOMParser parser;
                Poco::AutoPtr<Poco::XML::Document> pDoc = parser.parse(&src);
                Poco::AutoPtr<Poco::XML::NodeList> interestingFiles = pDoc->getElementsByTagName("INTERESTING_FILE");

                for (unsigned long i = 0; i < interestingFiles->length(); i++) {
                    Poco::XML::Node * pNode = interestingFiles->item(i);
                    Poco::AutoPtr<Poco::XML::NodeList>pChildren = pNode->childNodes();
                    string name;
                    string pathKeyword;
                    string extension;
                    string description;

                    for (unsigned long j = 0; j < pChildren->length(); j++) {
                        Poco::XML::Node * pNode = pChildren->item(j);

                        if (pNode->nodeType() == Poco::XML::Node::ELEMENT_NODE) {
                            wstringstream msg;
                            string tag = pNode->nodeName();

                            if (tag == "NAME") {
                                if (name == "") {
                                    name = pNode->innerText();
                                } else {
                                    // duplicated NAME
                                    msg << L"InterestingFiles: Multiple NAME specified in input file: " << name.c_str() << " and " << pNode->innerText().c_str();
                                    LOGERROR(msg.str());
                                    return TskModule::FAIL;
                                }
                            } else if (tag == "EXTENSION") {
                                if (extension == "") {
                                    extension = pNode->innerText();
                                } else {
                                    // duplicated EXTENSION
                                    msg << L"InterestingFiles: Multiple EXTENSION specified in input file: " << extension.c_str() << " and " << pNode->innerText().c_str();
                                    LOGERROR(msg.str());
                                    return TskModule::FAIL;
                                }
                            } else if (tag == "DESCRIPTION") {
                                description = pNode->innerText();
                            } else if (tag == "PATH_KEYWORD") {
                                if (pathKeyword == "") {
                                    pathKeyword = pNode->innerText();
                                } else {
                                    // duplicated PATH_KEYWORD
                                    msg << L"InterestingFiles: Multiple PATH_KEYWORD specified in input file: " << pathKeyword.c_str() << " and " << pNode->innerText().c_str();
                                    LOGERROR(msg.str());
                                    return TskModule::FAIL;
                                }
                            } else {
                                msg << L"InterestingFiles: Unknown element specified in input file: " << tag.c_str();
                                LOGERROR(msg.str());
                                return TskModule::FAIL;
                            }
                        } 
                    } 

                    wstringstream msg;
                    msg << "InterestingFiles: Rule: NAME=" << name.c_str() 
                        << " EXTENSION=" << extension.c_str()
                        //<< " PATH_KEYWORD=" << pathKeyword.c_str() 
                        << " DESCRIPTION=" << description.c_str();
                    LOGINFO(msg.str());

                    // Cannot have both NAME and EXTENSION
                    if (name != "" && extension != "") {
                        msg << L"InterestingFiles: Cannot specify both NAME and EXTENSION in input file: " << name.c_str() << " and " << extension.c_str();
                        LOGERROR(msg.str());
                        return TskModule::FAIL;
                    }

                    // Now search for files in database
                    string condition;
                    char escChar = '#';

                    condition = "WHERE ";
                    if (name != "") {
                        condition += "UPPER(name) = UPPER(" +  TskServices::Instance().getImgDB().quote(name) + ")";
                        addInterestingFilesToBlackboard(condition, description);
                    } else if (extension != "") {
                        condition += "UPPER(name) like UPPER('%" + escapeWildcard(extension, escChar) + "')";
                        condition += " ESCAPE '#'";
                        //printf("Searching for: %s\n", condition.c_str());
                        addInterestingFilesToBlackboard(condition, description);
                    }
                    else {
                        std::wstringstream msg;
                        msg << L"InterestingFiles - Skipping rule because NAME or EXTENSION were not specified";
                        LOGERROR(msg.str());
                        continue;
                    }
                    /*  REMOVING while we figure out the exact behavior we want
                    else if (pathKeyword != "") {
                        condition += "UPPER(full_path) like UPPER('%" + escapeWildcard(pathKeyword, escChar) + "%')";
                        condition += " ESCAPE '#'";
                        addInterestingFilesToBlackboard(condition, description);
                    }
                    */
                }

                return TskModule::OK;
            }
            catch (Poco::XML::SAXParseException& ex) {
                std::wstringstream msg;
                msg << L"InterestingFiles - Error parsing input file: " << ex.message().c_str();
                LOGERROR(msg.str());
                return TskModule::FAIL;
            }
            catch (TskException& ex) {
                std::wstringstream errorMsg;
                errorMsg << L"InterestingFiles - Error parsing XML Document or doing search: "
                         << ex.message().c_str() ;
                LOGERROR(errorMsg.str());
                return TskModule::FAIL;
            }
        } else {
            // Failed to find interesting files input file.
            wstringstream msg;
            msg << L"InterestingFiles - Cannot open input file: " << file.path().c_str();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        return TskModule::OK;
    }

    /**
     * Module cleanup function. This module does not need to free any resources 
     * allocated during initialization or execution.
     *
     * @returns TskModule::OK
     */
    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
        return TskModule::OK;
    }
}
