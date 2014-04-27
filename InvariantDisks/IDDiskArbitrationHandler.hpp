//
//  IDDiskArbitrationHandler.hpp
//  InvariantDisks
//
//  Created by Gerhard Röthlin on 2014.04.27.
//  Copyright (c) 2014 the-color-black.net. All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted
//  provided that the conditions of the "3-Clause BSD" license described in the LICENSE file are met.
//

#ifndef ID_DISKARBITRATIONHANDLER_HPP
#define ID_DISKARBITRATIONHANDLER_HPP

#include <DiskArbitration/DADisk.h>

namespace ID
{
	class DiskArbitrationHandler
	{
	public:
		virtual ~DiskArbitrationHandler() = default;

	public:
		virtual void diskAppeared(DADiskRef disk) = 0;
		virtual void diskDisappeared(DADiskRef disk) = 0;
	};
}

#endif
