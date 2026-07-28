import sys
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS


def get_gps_coords(exif_data):
    gps_info = {}
    for key, val in exif_data.items():
        tag = TAGS.get(key, key)
        if tag == "GPSInfo":
            for gps_key in val:
                gps_tag = GPSTAGS.get(gps_key, gps_key)
                gps_info[gps_tag] = val[gps_key]
    return gps_info


def main():
    if len(sys.argv) < 2:
        print("Error: No image path provided")
        sys.exit(1)

    image_path = sys.argv[1]

    try:
        image = Image.open(image_path)
    except Exception as e:
        print(f"Error: Could not open image ({e})")
        sys.exit(1)

    print(f"File Name: {image_path.split('/')[-1]}")
    print(f"Format: {image.format}")
    print(f"Mode: {image.mode}")
    print(f"Size: {image.width}x{image.height}")

    exif_data = image.getexif()

    if not exif_data:
        print("EXIF Data: None found")
        return

    for tag_id, value in exif_data.items():
        tag = TAGS.get(tag_id, tag_id)
        # Skip huge binary blobs (e.g. thumbnail data) to keep output readable
        if isinstance(value, bytes):
            continue
        print(f"{tag}: {value}")

    gps = get_gps_coords(exif_data)
    if gps:
        for key, value in gps.items():
            print(f"GPS {key}: {value}")


if __name__ == "__main__":
    main()