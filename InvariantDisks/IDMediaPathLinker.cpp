//
//  IDMediaPathLinker.cpp
//  InvariantDisks
//
//  Created by Gerhard Röthlin on 2014.04.27.
//  Copyright (c) 2014 the-color-black.net. All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted
//  provided that the conditions of the "3-Clause BSD" license described in the BSD.LICENSE file are met.
//  Additional licensing options are described in the README file.
//

#include "IDMediaPathLinker.hpp"

#include "IDDiskArbitrationUtils.hpp"
#include "IDFileUtils.hpp"

#include <iostream>
#include <algorithm>

namespace ID
{
	MediaPathLinker::MediaPathLinker(std::string base) :
		m_base(std::move(base))
	{
		createPath(m_base);
	}

	static std::string prefixDevice = "IODeviceTree:/";

	static std::string filterMediaPath(std::string const & mediaPath)
	{
		if (mediaPath.size() < prefixDevice.size())
			return std::string();
		auto r = std::mismatch(mediaPath.begin(), mediaPath.end(),
							   prefixDevice.begin());
		if (r.second != prefixDevice.end())
			return std::string();
		std::string filteredPath = mediaPath.substr(prefixDevice.size());
		std::replace(filteredPath.begin(), filteredPath.end(), '/', '-');
		return filteredPath;
	}

	void MediaPathLinker::diskAppeared(DADiskRef disk, DiskInformation const & di)
	{
		std::string mediaPath = filterMediaPath(di.mediaPath);
		if (!mediaPath.empty() && !di.mediaBSDName.empty())
		{
			try
			{
				mediaPath = m_base + "/" + mediaPath;
				std::string devicePath = "/dev/" + di.mediaBSDName;
				std::cout << "Creating symlink: \"" << mediaPath << "\" -> " << devicePath << std::endl;
				createSymlink(mediaPath, devicePath);
			}
			catch (std::exception const & e)
			{
				std::cerr << "Could not create symlink: " << e.what() << std::endl;
			}
		}
	}

	void MediaPathLinker::diskDisappeared(DADiskRef disk, DiskInformation const & di)
	{
		std::string mediaPath = filterMediaPath(di.mediaPath);
		if (!mediaPath.empty())
		{
			try
			{
				mediaPath = m_base + "/" + mediaPath;
				std::cout << "Removing symlink: \"" << mediaPath << "\"" << std::endl;
				removeSymlink(mediaPath);
			}
			catch (std::exception const & e)
			{
				std::cerr << "Could not remove symlink: " << e.what() << std::endl;
			}
		}
	}

}
