#include "stdafx.h"
#include "CppUnitTest.h"
#include "../EncryptionToolkit/KeyGenerator.h"
#include "../EncryptionToolkit/EncryptionToolkit.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace EncryptionTest
{
	TEST_CLASS(EncryptionToolkitTest)
	{
	public:

		TEST_METHOD(SaveFile_LoadFile_CheckFunctionality) //Checking whether save file can save data and load file can load back the same data.
		{
			std::string s = "";
			for (int i = 0; i < 256; i++) {
				char a = i;
				s += a;
			}

			Encryption::EncryptionToolkit toolkit;
			toolkit.save_file("unit_testing.bin", s);

			std::string file;
			toolkit.load_file("unit_testing.bin", file);

			Assert::IsTrue( file.compare(s)==0 );
		}

	};
}