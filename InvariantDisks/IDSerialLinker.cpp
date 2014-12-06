//
//  IDSerialLinker.cpp
//  InvariantDisks
//
//  Created by Gerhard Röthlin on 2014.05.03.
//  Copyright (c) 2014 the-color-black.net. All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted
//  provided that the conditions of the "3-Clause BSD" license described in the LICENSE file are met.
//

#include "IDSerialLinker.hpp"

#include "IDDiskArbitrationUtils.hpp"
#include "IDFileUtils.hpp"

#include <iostream>
#include <string>
#include <algorithm>

namespace ID
{
	SerialLinker::SerialLinker(std::string base) :
		m_base(std::move(base))
	{
		createPath(m_base);
	}

	static std::string prefixDevice = "IODeviceTree:/";

	bool isDevice(DiskInformation const & di)
	{
		return di.mediaPath.substr(0, prefixDevice.size()) == prefixDevice;
	}

	bool isWhole(DiskInformation const & di)
	{
		return di.mediaWhole;
	}

	static bool isInvalidSerialChar(char c)
	{
		if (isalnum(c))
			return false;
		if (c == '-' || c == '_')
			return false;
		return true;
	}

	std::string trim(std::string const & s)
	{
		size_t first = s.find_first_not_of(' ');
		size_t last = s.find_last_not_of(' ');
		return s.substr(first, last - first);
	}

	std::string partitionSuffix(DiskInformation const & di)
	{
		if (isDevice(di) && !isWhole(di))
		{
			size_t suffixStart = di.mediaPath.find_last_not_of("0123456789");
			if (suffixStart != std::string::npos && di.mediaPath[suffixStart] == ':')
				return di.mediaPath.substr(suffixStart);
		}
		return std::string();
	}

	std::string formatSerial(DiskInformation const & di)
	{
		std::string formated = trim(di.deviceModel) + "-" + trim(di.ioSerial);
		std::replace(formated.begin(), formated.end(), ' ', '_');
		formated.erase(std::remove_if(formated.begin(), formated.end(), isInvalidSerialChar), formated.end());
		formated += partitionSuffix(di);
		return formated;
	}

	std::string SerialLinker::formatSerialPath(DiskInformation const & di) const
	{
		return m_base + "/" + formatSerial(di);
	}

	void SerialLinker::diskAppeared(DADiskRef disk, DiskInformation const & di)
	{
		if (isDevice(di))
		{
			try
			{
				std::string serial = formatSerialPath(di);
				std::string devicePath = "/dev/" + di.mediaBSDName;
				std::cout << "Creating symlink: \"" << serial << "\" -> " << devicePath << std::endl;
				createSymlink(serial, devicePath);
			}
			catch (std::exception const & e)
			{
				std::cerr << "Could not create symlink: " << e.what() << std::endl;
			}
		}
	}

	void SerialLinker::diskDisappeared(DADiskRef disk, DiskInformation const & di)
	{
		if (isDevice(di))
		{
			try
			{
				std::string serial = formatSerialPath(di);
				std::string devicePath = "/dev/" + di.mediaBSDName;
				std::cout << "Removing symlink: \"" << serial << "\"" << std::endl;
				removeSymlink(serial);
			}
			catch (std::exception const & e)
			{
				std::cerr << "Could not remove symlink: " << e.what() << std::endl;
			}
		}
	}

}
