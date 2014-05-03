//
//  IDDiskInfoLogger.cpp
//  InvariantDisks
//
//  Created by Gerhard Röthlin on 2014.04.27.
//  Copyright (c) 2014 the-color-black.net. All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted
//  provided that the conditions of the "3-Clause BSD" license described in the LICENSE file are met.
//

#include "IDDiskInfoLogger.hpp"

#include "IDDiskArbitrationUtils.hpp"

#include <DiskArbitration/DiskArbitration.h>

#include <iostream>

namespace ID
{
	DiskInfoLogger::DiskInfoLogger(std::ostream & stream) :
		m_logStream(stream)
	{
	}

	void DiskInfoLogger::diskAppeared(DADiskRef /*disk*/, DiskInformation const & info)
	{
		m_logStream << "Disk Appeared: " << info << std::endl;
	}

	void DiskInfoLogger::diskDisappeared(DADiskRef /*disk*/, DiskInformation const & info)
	{
		m_logStream << "Disk Disappeared: " << info << std::endl;
	}
}
