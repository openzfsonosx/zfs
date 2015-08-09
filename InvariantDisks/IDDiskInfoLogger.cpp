//
//  IDDiskInfoLogger.cpp
//  InvariantDisks
//
//  Created by Gerhard Röthlin on 2014.04.27.
//  Copyright (c) 2014 the-color-black.net. All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted
//  provided that the conditions of the "3-Clause BSD" license described in the BSD.LICENSE file are met.
//  Additional licensing options are described in the README file.
//

#include "IDDiskInfoLogger.hpp"

#include "IDDiskArbitrationUtils.hpp"

#include <DiskArbitration/DiskArbitration.h>

#include <sstream>

namespace ID
{
	DiskInfoLogger::DiskInfoLogger(bool verbose, ASLClient const & logger) :
		DiskArbitrationHandler(logger),
		m_verbose(verbose)
	{
	}

	void DiskInfoLogger::diskAppeared(DADiskRef /*disk*/, DiskInformation const & info)
	{
		logger().log(ASL_LEVEL_NOTICE, "Disk Appeared: %s", formatDisk(info).c_str());
	}

	void DiskInfoLogger::diskDisappeared(DADiskRef /*disk*/, DiskInformation const & info)
	{
		logger().log(ASL_LEVEL_NOTICE, "Disk Disappeared: %s", formatDisk(info).c_str());
	}

	std::string DiskInfoLogger::formatDisk(DiskInformation const & info) const
	{
		std::stringstream ss;
		if (m_verbose)
			ss << info;
		else
			ss << info.mediaBSDName;
		return ss.str();
	}
}
