/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file InterestingFiles.cpp
 * This module looks for files matching criteria specified in an interesting 
 * files configuration file.
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

static const char *filename = "interesting_files.xml";
static string interestingFilesPath;

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
     * Module initialization function. Receives a string of intialization arguments, 
     * typically read by the caller from a pipeline configuration file. 
     * Returns TskModule::OK or TskModule::FAIL. Returning TskModule::FAIL indicates 
     * the module is not in an operational state.  
     *
     * @param args Initialization arguments.
     * @return TskModule::OK if initialization succeeded, otherwise TskModule::FAIL.
     */
    TskModule::Status TSK_MODULE_EXPORT initialize(std::string& args)
    {
        if (!args.empty()) {
            std::wstringstream msg;
            msg << L"InterestingFiles: Initialize with argument: " << TskUtilities::toUTF16(args);
            LOGINFO(msg.str().c_str());
            interestingFilesPath = args;
        }
        return TskModule::OK;
    }
    
    /**
     * Module execution function. Returns TskModule::OK, TskModule::FAIL, or TskModule::STOP. 
     * Returning TskModule::FAIL indicates error performing its job. Returning TskModule::STOP
     * is a request to terminate execution of the reporting pipeline.
     *
     * @returns TskModule::OK on success and TskModule::FAIL on error.
     */
    TskModule::Status TSK_MODULE_EXPORT report()
    {
        LOGINFO(L"InterestingFiles - report started.");
        if (!interestingFilesPath.length()) {
            // Path not provided via args, look for the interesting files config file in the output directory.
            interestingFilesPath = TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskSystemProperties::OUT_DIR));
            interestingFilesPath.append("\\");
            interestingFilesPath.append(filename);
        }
        Poco::File file = Poco::File(interestingFilesPath);
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
                                    msg << L"Multiple NAME specified in interesting_files.xml: " << name.c_str() << " and " << pNode->innerText().c_str();
                                    LOGERROR(msg.str());
                                    return TskModule::FAIL;
                                }
                            } else if (tag == "EXTENSION") {
                                if (extension == "") {
                                    extension = pNode->innerText();
                                } else {
                                    // duplicated EXTENSION
                                    msg << L"Multiple EXTENSION specified in interesting_files.xml: " << extension.c_str() << " and " << pNode->innerText().c_str();
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
                                    msg << L"Multiple PATH_KEYWORD specified in interesting_files.xml: " << pathKeyword.c_str() << " and " << pNode->innerText().c_str();
                                    LOGERROR(msg.str());
                                    return TskModule::FAIL;
                                }
                            } else {
                                msg << L"Unknown element specified in interesting_files.xml: " << tag.c_str();
                                LOGERROR(msg.str());
                                return TskModule::FAIL;
                            }

                            // Cannot have both NAME and EXTENSION
                            if (name != "" && extension != "") {
                                msg << L"Cannot specify both NAME and EXTENSION in interesting_files.xml: " << name.c_str() << " and " << extension.c_str();
                                LOGERROR(msg.str());
                                return TskModule::FAIL;
                            }
                        } 
                    } 

                    wstringstream msg;
                    msg << "NAME=" << name.c_str() 
                        << " EXTENSION=" << extension.c_str()
                        << " PATH_KEYWORD=" << pathKeyword.c_str() 
                        << " DESCRIPTION=" << description.c_str();
                    LOGINFO(msg.str());

                    // Now search for files in database
                    string condition;
                    char escChar = '#';

                    condition = "WHERE ";
                    if (name != "") {
                        condition += "UPPER(name) = UPPER(" +  TskServices::Instance().getImgDB().quote(name) + ")";
                        if (pathKeyword != "") {
                            condition += " AND UPPER(full_path) like UPPER('%" + escapeWildcard(pathKeyword, escChar) + "%' ESCAPE '#')";
                        }
                        condition += " ORDER BY file_id";
                        addInterestingFilesToBlackboard(condition, description);
                    } else if (extension != "") {
                        condition += "UPPER(name) like UPPER('%" + escapeWildcard(extension, escChar) + "')";
                        if (pathKeyword != "") {
                            condition += " AND UPPER(full_path) like UPPER('%" + escapeWildcard(pathKeyword, escChar) + "%')";
                        }
                        condition += " ESCAPE '#' ORDER BY file_id";
                        addInterestingFilesToBlackboard(condition, description);
                    }
                }

                return TskModule::OK;
            }
            catch (Poco::XML::SAXParseException& ex) {
                std::wstringstream msg;
                msg << L"InterestingFiles - Error parsing interesting_files.xml: " << ex.message().c_str();
                LOGERROR(msg.str());
                return TskModule::FAIL;
            }
            catch (TskException& ex) {
                std::wstringstream errorMsg;
                errorMsg << L"InterestingFiles - Error creating XML Document: "
                         << ex.message().c_str() ;
                LOGERROR(errorMsg.str());
                return TskModule::FAIL;
            }
        } else {
            // Failed to find interesting files config file.
            wstringstream msg;
            msg << L"InterestingFiles - Cannot open file: " << file.path().c_str();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        return TskModule::OK;
    }

    /**
     * Module cleanup function. This is where the module should free any resources 
     * allocated during initialization or execution.
     *
     * @returns TskModule::OK on success and TskModule::FAIL on error.
     */
    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
        return TskModule::OK;
    }
}
