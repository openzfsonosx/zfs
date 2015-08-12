//
//  IDASLUtils.cpp
//  InvariantDisks
//
//  Created by Gerhard Röthlin on 2015.08.01.
//  Copyright (c) 2015 the-color-black.net. All rights reserved.
//

#include "IDASLUtils.hpp"

#include <vector>
#include <algorithm>

#include <unistd.h>
#include <fcntl.h>

namespace ID
{
	class ASLClient::Impl
	{
	public:
		Impl(char const * ident, char const * facility, uint32_t opts) :
			client(asl_open(ident, facility, opts))
		{
		}

		~Impl()
		{
			asl_close(client);
			for (auto fd: fds)
				close(fd);
		}

	public:
		Impl(Impl const &) = delete;
		Impl & operator=(Impl const &) = delete;

	public:
		int addLogFile(char const * logFile)
		{
			int fd = open(logFile, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
			if (fd < 0)
			{
				asl_log(client, 0, ASL_LEVEL_ERR, "Error opening log file \"%s\" (%m)", logFile);
				return -1;
			}
			int r = asl_add_log_file(client, fd);
			if (r != 0)
			{
				asl_log(client, 0, ASL_LEVEL_ERR, "Error registering file \"%s\" (%d)", logFile, r);
				close(fd);
				return -1;
			}
			fds.push_back(fd);
			return fd;
		}

		void removeLogFile(int fd)
		{
			auto found = std::find(fds.begin(), fds.end(), fd);
			if (found != fds.end())
			{
				std::swap(*found, fds.back());
				fds.pop_back();
				asl_remove_log_file(client, fd);
				close(fd);
			}
		}

	public:
		aslclient client;
		std::vector<int> fds;
	};


	ASLClient::ASLClient(char const * ident, char const * facility, uint32_t opts) :
		m_impl(std::make_shared<Impl>(ident, facility, opts))
	{
	}

	aslclient ASLClient::client() const
	{
		return m_impl->client;
	}

	int ASLClient::addLogFile(char const * logFile)
	{
		return m_impl->addLogFile(logFile);
	}

	void ASLClient::logFormat(int level, const char * format, ...) const
	{
		va_list args;
		va_start(args, format);
		asl_vlog(client(), 0, level, format, args);
		va_end(args);
	}
}
