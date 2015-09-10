//
//  IDASLUtils.h
//  InvariantDisks
//
//  Created by Gerhard Röthlin on 2015.08.01.
//  Copyright (c) 2015 the-color-black.net. All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted
//  provided that the conditions of the "3-Clause BSD" license described in the BSD.LICENSE file are met.
//  Additional licensing options are described in the README file.
//

#ifndef ID_ASLUTILS_HPP
#define ID_ASLUTILS_HPP

#include <asl.h>

#include <memory>
#include <sstream>

namespace ID
{
	class ASLClient
	{
	public:
		explicit ASLClient(char const * ident, char const * facility, uint32_t opts);

	public:
		aslclient client() const;

	public:
		int addLogFile(char const * logFile);

	public:
		template<typename... ARGS>
		void log(int level, ARGS const & ... args) const;

		void logFormat(int level, const char * format, ...) const __printflike(3, 4);

	private:
		class Impl;
		std::shared_ptr<Impl> m_impl;
	};

	// Private Implementation
	template<typename... ARGS>
	void ASLClient::log(int level, ARGS const & ... args) const
	{
		std::stringstream ss;
		int ignored[] = {(ss << args, 0)...};
		(void)ignored;
		asl_log(client(), 0, level, "%s", ss.str().c_str());
	}
}

#endif
