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

#include <iostream>

namespace ID
{
	DiskInfoLogger::DiskInfoLogger(std::ostream & stream, bool verbose) :
		m_logStream(stream), m_verbose(verbose)
	{
	}

	void DiskInfoLogger::diskAppeared(DADiskRef /*disk*/, DiskInformation const & info)
	{
		m_logStream << "Disk Appeared: ";
		printDisk(info);
		m_logStream << std::endl;
	}

	void DiskInfoLogger::diskDisappeared(DADiskRef /*disk*/, DiskInformation const & info)
	{
		m_logStream << "Disk Disappeared: ";
		printDisk(info);
		m_logStream << std::endl;
	}

	void DiskInfoLogger::printDisk(DiskInformation const & info) const
	{
		if (m_verbose)
			m_logStream << info;
		else
			m_logStream << info.mediaBSDName;
	}
}
