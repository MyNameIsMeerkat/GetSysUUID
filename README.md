#GetSysUUID

A little Python module that provides the functionality to get a SYSUUID
from the [SMBIOS](http://www.dmtf.org/standards/published_documents/DSP0134_2.6.1.pdf) in a cross-platform Pythonic way.

The module works on both 32 and 64 bit versions of Windows, Linux and OS X.

For Linux and OS X it just calls out to the relevent command line tool (`dmidecode` or `ioreg`) and parses the output into a normalised form. For Windows it uses `ctypes` to call out to the `GetSystemFirmwareTable` function and parse the results.

Except in buggy SMBIOS implementations (of which there are unfortunately quite a few) the UUID returned should be unique to a system and thus be identifying.

##Usage

`GetSysUUID` is very straight forward to use:

```
import GetSysUUID
sysuuid = GetSysUUID.GetSysUUID()
print sysuuid()
```

Would produce an example output of:

```
UUID: D2AC346E-E323-5F2E-7C2D-D5783E5E14DB
```

##License
`GetSysUUID` is released under the [LGPL](http://www.gnu.org/licenses/lgpl.html).
