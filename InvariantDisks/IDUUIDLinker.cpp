//
//  IDUUIDLinker.cpp
//  InvariantDisks
//
//  Created by Gerhard Röthlin on 2014.05.03.
//  Copyright (c) 2014 the-color-black.net. All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted
//  provided that the conditions of the "3-Clause BSD" license described in the BSD.LICENSE file are met.
//  Additional licensing options are described in the README file.
//

#include "IDUUIDLinker.hpp"

#include "IDDiskArbitrationUtils.hpp"
#include "IDFileUtils.hpp"

#include <vector>

namespace ID
{
	UUIDLinker::UUIDLinker(std::string base, ASLClient const & logger) :
		DiskArbitrationHandler(logger),
		m_base(std::move(base))
	{
		createPath(m_base);
	}

	static std::vector<std::string> getUUIDs(DiskInformation const & diskInfo)
	{
		std::vector<std::string> uuids;
		if (!diskInfo.volumeUUID.empty())
			uuids.push_back("volume-" + diskInfo.volumeUUID);
		if (!diskInfo.mediaUUID.empty())
			uuids.push_back("media-" + diskInfo.mediaUUID);
		if (!diskInfo.deviceGUID.empty())
			uuids.push_back("device-" + diskInfo.deviceGUID);
		return uuids;
	}

	void UUIDLinker::diskAppeared(DADiskRef disk, DiskInformation const & di)
	{
		auto mediaUUIDs = getUUIDs(di);
		for (auto mediaID: mediaUUIDs)
		{
			try
			{
				mediaID = m_base + "/" + mediaID;
				std::string devicePath = "/dev/" + di.mediaBSDName;
				logger().log(ASL_LEVEL_NOTICE, "Creating symlink: \"%s\" -> \"%s\"",
							 mediaID.c_str(), devicePath.c_str());
				createSymlink(mediaID, devicePath);
			}
			catch (std::exception const & e)
			{
				logger().log(ASL_LEVEL_ERR, "Could not create symlink: %s", e.what());
			}
		}
	}

	void UUIDLinker::diskDisappeared(DADiskRef disk, DiskInformation const & di)
	{
		auto mediaUUIDs = getUUIDs(di);
		for (auto mediaID: mediaUUIDs)
		{
			try
			{
				mediaID = m_base + "/" + mediaID;
				logger().log(ASL_LEVEL_NOTICE, "Removing symlink: \"%s\"", mediaID.c_str());
				removeFSObject(mediaID);
			}
			catch (std::exception const & e)
			{
				logger().log(ASL_LEVEL_ERR, "Could not remove symlink: %s", e.what());
			}
		}
	}

}
