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

#include <algorithm>

namespace ID
{
	MediaPathLinker::MediaPathLinker(std::string base, ASLClient const & logger) :
		DiskArbitrationHandler(logger),
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
				asl_log(logger().client(), 0, ASL_LEVEL_NOTICE,
						"Creating symlink: \"%s\" -> \"%s\"",
						mediaPath.c_str(), devicePath.c_str());
				createSymlink(mediaPath, devicePath);
			}
			catch (std::exception const & e)
			{
				asl_log(logger().client(), 0, ASL_LEVEL_ERR,
						"Could not create symlink: %s", e.what());
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
				asl_log(logger().client(), 0, ASL_LEVEL_NOTICE,
						"Removing symlink: \"%s\"", mediaPath.c_str());
				removeFSObject(mediaPath);
			}
			catch (std::exception const & e)
			{
				asl_log(logger().client(), 0, ASL_LEVEL_ERR,
						"Could not remove symlink: %s", e.what());
			}
		}
	}

}
