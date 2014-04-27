//
//  IDDiskArbitrationUtils.hpp
//  InvariantDisks
//
//  Created by cbreak on 2014.04.27.
//  Copyright (c) 2014 the-color-black.net. All rights reserved.
//

#ifndef ID_DISKARBITRATIONUTILS_HPP
#define ID_DISKARBITRATIONUTILS_HPP

#include <DiskArbitration/DiskArbitration.h>

#include <iostream>
#include <string>

namespace ID
{
	struct DiskInformation
	{
		std::string volumeKind;
		std::string volumeUUID;
		std::string volumeName;
		std::string mediaKind;
		std::string mediaUUID;
		std::string mediaBSDName;
		std::string mediaName;
		std::string mediaPath;
		std::string deviceGUID;
		std::string busName;
		std::string busPath;
	};

	DiskInformation getDiskInformation(DADiskRef disk);

	std::ostream & operator<<(std::ostream & os, DADiskRef disk);
	std::ostream & operator<<(std::ostream & os, DiskInformation const & disk);
}

#endif
