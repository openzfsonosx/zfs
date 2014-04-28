//
//  IDFileUtils.cpp
//  InvariantDisks
//
//  Created by Gerhard Röthlin on 2014.04.27.
//  Copyright (c) 2014 the-color-black.net. All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted
//  provided that the conditions of the "3-Clause BSD" license described in the LICENSE file are met.
//

#include "IDFileUtils.hpp"

#include "IDException.hpp"

#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

namespace ID
{
	static void throwOnError(int error, char const * command)
	{
		if (error)
		{
			Throw<Exception> e;
			e << "Error executing " << command << ": " << strerror(errno);
		}
	}

#define EXEC_THROW(c) throwOnError((c), #c)

	void createPath(std::string const & path)
	{
		size_t slashIdx = 0;
		do
		{
			slashIdx = path.find('/', slashIdx+1);
			int err = mkdir(path.substr(0, slashIdx).c_str(), 0755); // octal mode
			if (err != 0 && errno != EEXIST)
				throw Exception("Error creating Directory: " + path);
		}
		while (slashIdx != std::string::npos);
	}

	void createSymlink(std::string const & link, std::string const & target)
	{
		// Remove old symlink if it exists
		if (access(link.c_str(), F_OK) == 0)
			EXEC_THROW(unlink(link.c_str()));
		EXEC_THROW(symlink(target.c_str(), link.c_str()));
	}

	void removeSymlink(std::string const & link)
	{
		EXEC_THROW(unlink(link.c_str()));
	}
}
