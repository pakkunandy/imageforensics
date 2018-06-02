# Digital Image Forensics

## Overview
I gathered some techniques in some paper and composed the small tools that implement those methods in DIF. The tool does not tell exactly this image is forged/photoshoped/tampered or not (even if some tool can tell exactly forged or not, you can go directly to the top of the world).   This tools just give some warning, some weird “information” of the image, visual some strange region of the image to the users. Then, based on that information the users can make the decisions.

Nowadays, the tampered image is more difficult to detect. Many techniques that counter the detection. My tool implements some techniques are a little bit old, but still useful in some image. Some tampered images are easy to detect by these methods but hard to detect by the others. Therefore, we need to combine many techniques to analyze one images.

## Requirement
* [Python 2.7](https://www.python.org/)
* Python Libraries:
  * [exifread](https://pypi.org/project/ExifRead/)
   * [opencv-python](https://pypi.org/project/opencv-python/)
   * [progressbar2](https://pypi.org/project/progressbar2/)
   * [Numpy](http://www.numpy.org/)
   * [Scipy](https://www.scipy.org/install.html)
   * Pillow(https://pillow.readthedocs.io/en/5.1.x/installation.html)
   * PyWavelets(http://pywavelets.readthedocs.io/en/latest/)
