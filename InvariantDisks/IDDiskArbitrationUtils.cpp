//
//  IDDiskArbitrationUtils.cpp
//  InvariantDisks
//
//  Created by Gerhard Röthlin on 2014.04.27.
//  Copyright (c) 2014 the-color-black.net. All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted
//  provided that the conditions of the "3-Clause BSD" license described in the LICENSE file are met.
//

#include "IDDiskArbitrationUtils.hpp"

namespace ID
{
	std::ostream & operator<<(std::ostream & os, DADiskRef disk)
	{
		return os << getDiskInformation(disk);
	}

	std::ostream & operator<<(std::ostream & os, DiskInformation const & disk)
	{
		return os << "Disk: (\n"
			<< "\tVolumeKind=\"" << disk.volumeKind << "\"\n"
			<< "\tVolumeUUID=\"" << disk.volumeUUID << "\"\n"
			<< "\tVolumeName=\"" << disk.volumeName << "\"\n"
			<< "\tVolumePath=\"" << disk.volumePath << "\"\n"
			<< "\tMediaKind=\"" << disk.mediaKind << "\"\n"
			<< "\tMediaUUID=\"" << disk.mediaUUID << "\"\n"
			<< "\tMediaBSDName=\"" << disk.mediaBSDName << "\"\n"
			<< "\tMediaName=\"" << disk.mediaName << "\"\n"
			<< "\tMediaPath=\"" << disk.mediaPath << "\"\n"
			<< "\tMediaContent=\"" << disk.mediaContent << "\"\n"
			<< "\tDeviceGUID=\"" << disk.deviceGUID << "\"\n"
			<< "\tDevicePath=\"" << disk.devicePath << "\"\n"
			<< "\tBusName=\"" << disk.busName << "\"\n"
			<< "\tBusPath=\"" << disk.busPath << "\"\n"
			<< ")";
	}

	std::string to_string(CFStringRef str)
	{
		std::string result;
		CFRange strRange = CFRangeMake(0, CFStringGetLength(str));
		CFIndex strBytes = 0;
		CFStringGetBytes(str, strRange, kCFStringEncodingUTF8, 0, false, nullptr, 0, &strBytes);
		if (strBytes > 0)
		{
			result.resize(static_cast<size_t>(strBytes), '\0');
			CFStringGetBytes(str, strRange, kCFStringEncodingUTF8, 0, false,
							 reinterpret_cast<UInt8*>(&result[0]), strBytes, nullptr);
		}
		return result;
	}

	std::string to_string(CFURLRef url)
	{
		CFStringRef str = CFURLCopyPath(url);
		std::string result = to_string(str);
		CFRelease(str);
		return result;
	}

	std::string to_string(CFDataRef data)
	{
		return std::string(reinterpret_cast<char const *>(CFDataGetBytePtr(data)), CFDataGetLength(data));
	}

	std::string to_string(CFUUIDRef uuid)
	{
		CFStringRef str = CFUUIDCreateString(kCFAllocatorDefault, uuid);
		std::string result = to_string(str);
		CFRelease(str);
		return result;
	}

	template<typename T>
	std::string stringFromDictionary(CFDictionaryRef dict, CFStringRef key)
	{
		if (T value = static_cast<T>(CFDictionaryGetValue(dict, key)))
			return to_string(value);
		return std::string();
	}

	int64_t numberFromDictionary(CFDictionaryRef dict, CFStringRef key)
	{
		if (CFNumberRef value = static_cast<CFNumberRef>(CFDictionaryGetValue(dict, key)))
		{
			int64_t number = 0;
			CFNumberGetValue(value, kCFNumberSInt64Type, &number);
			return number;
		}
		return 0;
	}

	DiskInformation getDiskInformation(DADiskRef disk)
	{
		DiskInformation info;
		CFDictionaryRef descDict = DADiskCopyDescription(disk);
		info.volumeKind = stringFromDictionary<CFStringRef>(descDict, kDADiskDescriptionVolumeKindKey);
		info.volumeUUID = stringFromDictionary<CFUUIDRef>(descDict, kDADiskDescriptionVolumeUUIDKey);
		info.volumeName = stringFromDictionary<CFStringRef>(descDict, kDADiskDescriptionVolumeNameKey);
		info.volumePath = stringFromDictionary<CFURLRef>(descDict, kDADiskDescriptionVolumePathKey);
		info.mediaKind = stringFromDictionary<CFStringRef>(descDict, kDADiskDescriptionMediaKindKey);
		info.mediaUUID = stringFromDictionary<CFUUIDRef>(descDict, kDADiskDescriptionMediaUUIDKey);
		info.mediaBSDName = stringFromDictionary<CFStringRef>(descDict, kDADiskDescriptionMediaBSDNameKey);
		info.mediaName = stringFromDictionary<CFStringRef>(descDict, kDADiskDescriptionMediaNameKey);
		info.mediaPath = stringFromDictionary<CFStringRef>(descDict, kDADiskDescriptionMediaPathKey);
		info.mediaContent = stringFromDictionary<CFStringRef>(descDict, kDADiskDescriptionMediaContentKey);
		info.deviceGUID = stringFromDictionary<CFDataRef>(descDict, kDADiskDescriptionDeviceGUIDKey);
		info.devicePath = stringFromDictionary<CFStringRef>(descDict, kDADiskDescriptionDevicePathKey);
		info.busName = stringFromDictionary<CFStringRef>(descDict, kDADiskDescriptionBusNameKey);
		info.busPath = stringFromDictionary<CFStringRef>(descDict, kDADiskDescriptionBusPathKey);
		CFRelease(descDict);
		io_service_t io = DADiskCopyIOMedia(disk);
		CFMutableDictionaryRef ioDict = nullptr;
		if (IORegistryEntryCreateCFProperties(io, &ioDict, kCFAllocatorDefault, 0) == kIOReturnSuccess)
		{
			// TODO: Pick out useful IOKit properties
			CFRelease(ioDict);
		}
		IOObjectRelease(io);
		return info;
	}
}
