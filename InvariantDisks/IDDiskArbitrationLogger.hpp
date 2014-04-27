//
//  IDDiskArbitrationLogger.hpp
//  InvariantDisks
//
//  Created by cbreak on 2014.04.27.
//  Copyright (c) 2014 the-color-black.net. All rights reserved.
//

#ifndef ID_DISKARBITRATIONLOGGER_HPP
#define ID_DISKARBITRATIONLOGGER_HPP

#include "IDDiskArbitrationHandler.hpp"

#include <iostream>

namespace ID
{
	class DiskArbitrationLogger : public DiskArbitrationHandler
	{
	public:
		DiskArbitrationLogger(std::ostream & stream);

	public:
		virtual void diskAppeared(DADiskRef disk) override;
		virtual void diskDisappeared(DADiskRef disk) override;

	private:
		std::ostream & m_logStream;
	};
}

#endif
