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

	void createSymlink(std::string const & link, std::string const & target)
	{
		if (link.empty() || target.empty())
			throw Exception("Can not create symlink with empty path");
		removeSymlink(link);
		int err = symlink(target.c_str(), link.c_str());
		if (err != 0)
		{
			Throw<Exception> e;
			e << "Error creating symlink " << link << " pointing to " << target << ": " << strerror(err);
		}
	}

	void removeSymlink(std::string const & link)
	{
		if (link.empty())
			throw Exception("Can not remove symlink with empty path");
		int err = unlink(link.c_str());
		if (err != 0 && errno != ENOENT)
		{
			Throw<Exception> e;
			e << "Error removing symlink " << link << ": " << strerror(err);
		}
	}
}
