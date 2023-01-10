// This is just a copy of the autologin decrypt code in standalone form

#include <algorithm>
#include <iostream>
#include <vector>
#include <Windows.h>
#include <wincrypt.h>

#pragma comment(lib, "Crypt32.lib")

inline void MakeLower(std::string& str)
{
	std::transform(str.begin(), str.end(), str.begin(), ::tolower);
}

bool DecryptData(DATA_BLOB* DataIn, DATA_BLOB* DataOut)
{
	return CryptUnprotectData(DataIn, nullptr, nullptr, nullptr, nullptr, 0, DataOut) != 0;
}

int StrToBlob(const std::string& stringIn, DATA_BLOB* BlobOut)
{
	std::string temp = stringIn;
	MakeLower(temp);

	uint8_t* pbData = (uint8_t*)LocalAlloc(LPTR, temp.length() + 1);
	size_t out = 0;

	for (int count = 0; temp[count]; count += 2, out++)
	{
		if (((temp[count] < '0' || temp[count] > '9')
			&& (temp[count] < 'a' || temp[count] > 'f'))
			|| ((temp[count + 1] < '0' || temp[count + 1] > '9')
				&& (temp[count + 1] < 'a' || temp[count + 1] > 'f')))
		{
			break;
		}

		uint8_t CurByte = 0;

		if (temp[count] >= '0' && temp[count] <= '9')
			CurByte = temp[count] - '0';
		else if (temp[count] >= 'a' && temp[count] <= 'f')
			CurByte = temp[count] - 87;

		CurByte <<= 4;

		if (temp[count + 1] >= '0' && temp[count + 1] <= '9')
			CurByte |= temp[count + 1] - '0';
		else if (temp[count + 1] >= 'a' && temp[count + 1] <= 'f')
			CurByte |= temp[count + 1] - 87;

		pbData[out] = CurByte;
	}
	pbData[out++] = 0;

	BlobOut->cbData = out;
	BlobOut->pbData = pbData;
	return BlobOut->cbData;
}

int BlobToStr(DATA_BLOB* Blob, std::string& outString)
{
	uint8_t* pb = Blob->pbData;
	char out[2048];
	char* szOut = out;

	for (size_t i = 0; i < Blob->cbData; i++, pb++)
	{
		int b = (*pb & 0xF0) >> 4;
		*szOut++ = (char)((b <= 9) ? b + '0' : (b - 10) + 'A');

		b = *pb & 0x0F;
		*szOut++ = (char)((b <= 9) ? b + '0' : (b - 10) + 'A');
	}
	*szOut++ = 0;

	outString = out;
	return Blob->cbData;
}

inline std::vector<std::string_view> split_view(std::string_view s, char delim)
{
	std::vector<std::string_view> elems;

	size_t start_idx = 0;

	for (size_t i = 0; i < s.size(); ++i)
	{
		if (s[i] == delim)
		{
			elems.emplace_back(s.data() + start_idx, i - start_idx);
			start_idx = i + 1;
		}
	}

	return elems;
}


int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		std::cout << "This program only accepts 1 argument, the string to be decrypted.  Paste the entire line (quoted) from your autologin.ini";
	}
	else
	{
		std::string inStr = argv[1];
		const size_t firstColon = inStr.find(':');
		if (firstColon == std::string::npos)
		{
			std::cout << "Format incorrect, could not find a colon, did you paste the whole line?";
		}
		else
		{
			const size_t blobLoc = inStr.find("_Blob");
			if (blobLoc == std::string::npos)
			{
				std::cout << "_Blob not found, did you paste the whole line?";
			}
			else
			{
				const size_t firstEqual = inStr.find('=');
				if (firstEqual == std::string::npos)
				{
					std::cout << "Format incorrect, could not find an equals sign, did you paste the whole line?";
				}
				else
				{
					std::string ServerName = inStr.substr(0, firstColon);
					std::string CharName = inStr.substr(firstColon + 1, blobLoc - firstColon - 1);
					std::string bigBlobby = inStr.substr(firstEqual + 1);
					bigBlobby = bigBlobby.substr(0, bigBlobby.length() - 2);

					DATA_BLOB db, dbout;
					if (!bigBlobby.empty() && StrToBlob(bigBlobby.c_str(), &db))
					{
						if (DecryptData(&db, &dbout) && dbout.pbData != nullptr)
						{
							std::vector<std::string_view> tokens = split_view(reinterpret_cast<const char*>(dbout.pbData), ':');
							switch (tokens.size())
							{
								default:
								case 6:
									std::cout << "Level: " << tokens[5] << std::endl;
								case 5:
									std::cout << "Class: " << tokens[4] << std::endl;
								case 4:
									std::cout << "Hotkey: " << tokens[3] << std::endl;
								case 3:
									std::cout << "Password: " << tokens[2] << std::endl;
								case 2:
									std::cout << "Character Name: " << tokens[1] << std::endl;
								case 1:
									std::cout << "Account Name: " << tokens[0] << std::endl;
								case 0:
									std::cout << "Server: " << ServerName << std::endl;
									std::cout << "Character (again): " << CharName << std::endl;
									break;
							}
						}
						else
						{
							std::cout << "Could not decrypt blob, sorry!" << std::endl;
						}
					}
					else
					{
						std::cout << "Something went wrong with the blob." << std::endl;
					}
				}
			}
		}
	}
}