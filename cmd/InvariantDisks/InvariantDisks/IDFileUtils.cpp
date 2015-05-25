//
//  IDFileUtils.cpp
//  InvariantDisks
//
//  Created by Gerhard Röthlin on 2014.04.27.
//  Copyright (c) 2014 the-color-black.net. All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted
//  provided that the conditions of the "3-Clause BSD" license described in the BSD.LICENSE file are met.
//  Additional licensing options are described in the README file.
//

#include "IDFileUtils.hpp"

#include "IDException.hpp"

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

namespace ID
{
	void createPath(std::string const & path)
	{
		size_t slashIdx = 0;
		do
		{
			slashIdx = path.find('/', slashIdx+1);
			int err = mkdir(path.substr(0, slashIdx).c_str(), 0755); // octal mode
			if (err != 0 && errno != EEXIST)
			{
				Throw<Exception> e;
				e << "Error creating Directory: " << path;
			}
		}
		while (slashIdx != std::string::npos);
	}

	void createFile(std::string const & path)
	{
		if (path.empty())
			throw Exception("Can not create file with empty path");
		removeFSObject(path);
		// Create the file for event use only with user-readability only
		int fd = open(path.c_str(), O_EVTONLY | O_CREAT, 0700);
		if (fd >= 0)
		{
			close(fd);
		}
		else
		{
			Throw<Exception> e;
			e << "Error creating file " << path << ": " << strerror(errno);
		}
	}

	void createSymlink(std::string const & link, std::string const & target)
	{
		if (link.empty() || target.empty())
			throw Exception("Can not create symlink with empty path");
		removeFSObject(link);
		int err = symlink(target.c_str(), link.c_str());
		if (err != 0)
		{
			Throw<Exception> e;
			e << "Error creating symlink " << link << " pointing to " << target << ": " << strerror(err);
		}
	}

	void removeFSObject(std::string const & path)
	{
		if (path.empty())
			throw Exception("Can not remove file system object with empty path");
		int err = unlink(path.c_str());
		if (err != 0 && errno != ENOENT)
		{
			Throw<Exception> e;
			e << "Error removing file system object " << path << ": " << strerror(err);
		}
	}
}
