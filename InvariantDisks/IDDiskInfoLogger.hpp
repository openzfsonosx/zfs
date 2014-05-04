//
//  IDDiskInfoLogger.hpp
//  InvariantDisks
//
//  Created by Gerhard Röthlin on 2014.04.27.
//  Copyright (c) 2014 the-color-black.net. All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted
//  provided that the conditions of the "3-Clause BSD" license described in the LICENSE file are met.
//

#ifndef ID_DISKINFOLOGGER_HPP
#define ID_DISKINFOLOGGER_HPP

#include "IDDiskArbitrationHandler.hpp"

#include <iostream>

namespace ID
{
	class DiskInfoLogger : public DiskArbitrationHandler
	{
	public:
		DiskInfoLogger(std::ostream & stream, bool verbose = false);

	public:
		virtual void diskAppeared(DADiskRef disk, DiskInformation const & info) override;
		virtual void diskDisappeared(DADiskRef disk, DiskInformation const & info) override;

	private:
		void printDisk(DiskInformation const & info) const;

	private:
		std::ostream & m_logStream;
		bool m_verbose;
	};
}

#endif
