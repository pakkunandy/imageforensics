# Digital Image Forensics

## Overview
I gathered some techniques in some paper and composed the small tools that implement those methods in DIF. The tool does not tell exactly this image is forged/photoshoped/tampered or not (even if some tool can tell exactly forged or not, you can go directly to the top of the world).   This tools just give some warning, some weird “information” of the image, visual some strange region of the image to the users. Then, based on that information the users can make the decisions.

Nowadays, the tampered image is more difficult to detect. Many techniques that counter the detection. My tool implements some techniques are a little bit old, but still useful in some image. Some tampered images are easy to detect by these methods but hard to detect by the others. Therefore, we need to combine many techniques to analyze one images.

## Requirement
* [Python 3](https://www.python.org/)
* [PIP](https://pip.pypa.io/en/stable/installing/)
* Python Libraries:
  * [exifread](https://pypi.org/project/ExifRead/)
  * [opencv-python](https://pypi.org/project/opencv-python/)
  * [progressbar2](https://pypi.org/project/progressbar2/)
  * [Numpy](http://www.numpy.org/)
  * [Scipy](https://www.scipy.org/install.html)
  * [Pillow](https://pillow.readthedocs.io/en/5.1.x/installation.html)
  * [PyWavelets](http://pywavelets.readthedocs.io/en/latest/)
  * [Matplotlib](https://matplotlib.org/users/installing.html)

Or, Simply run command to install the packets:
```bash
  ./install_packet.sh
```
 
## Functions
### 1. Analysing using Metadata EXIF header
```
python foreimg.py exif1.jpg
```
or:
```
python foreimg.py -e exif1.jpg
```

After you run the command, the Warning and the detail of EXIF will be shown.
(This is the default function)

More to test:
```
python foreimg.py exif2.jpg
python foreimg.py exif3.jpg
```

### 2. Exposing digital forgeries by JPEG Ghost
```
python foreimg.py -g demo.jpg
```

Or multiple version:

```
python foreimg.py -gm demo.jpg
```

After you run the command, the tampered region is highlight with dark color.

More:
You can choose the quality of the resaved image:

```
python foreimg.py -g -q 50 demo.jpg
```

### 3. Exposing digital forgeries by Noise Inconsistencies
```
python foreimg.py -n1 demo.jpg
```
After you run the command, the tampered region is highlight with dark color.

You also can chosse the block size kernel:

```
python foreimg.py -n1 -s 7 demo.jpg
```

### 4. Exposing digital forgeries by Median-filter noise residue inconsistencies
```
python foreimg.py -n2 demo.jpg
```
After you run the command, the tampered region is highlight with dark color.

You also can chosse the block size kernel:

```
python foreimg.py -n2 -s 7 demo.jpg
```

### 5. Exposing digital forgeries by Error Level Analysis (ELA):
```
python foreimg.py -el demo.jpg
```
After you run the command, the tampered region is highlight with dark color.

You also can chosse the quality of resaved image and the block size kernel:

```
python foreimg.py -el -q 90 -s 7 demo.jpg
```

### 6. Exposing digital forgeries by demosaicing artifacts (CFA):
```
python foreimg.py -cf demo.jpg
```
After you run the command, the tampered region is highlight with dark color.

(this will take a little bit longer the previous ones)


For more information about the command, you can type:

```
python foreimg.py -h
```

For more information about the theory, you can check the [REPORT.pdf](https://github.com/anhduy41294/imageforensics/blob/master/REPORT.pdf).

## Commands Sumamry

```bash
python foreimg.py exif1.jpg
python foreimg.py exif2.jpg
python foreimg.py exif3.jpg
python foreimg.py -g demo.jpg
python foreimg.py -gm demo.jpg
python foreimg.py -n1 demo.jpg
python foreimg.py -n2 demo.jpg
python foreimg.py -el demo.jpg
python foreimg.py -cf demo.jpg
```

The folder contains the `exif*.jpg` for testing with EXIF, and `demo*.jpg` for testing with other methods. You can play around with those images. The quality of the tool is as well as with the online tool [Forensically](https://29a.ch/photo-forensics/#forensic-magnifier)
