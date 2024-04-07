import shutil
import tempfile

import unittest
from source_build import Blob, OCIImage
from test_source_build import create_blob, create_local_oci_image


class TestBlob(unittest.TestCase):
    """Test class Blob"""

    def setUp(self):
        self.image_dir = tempfile.mkdtemp()
        self.descriptor = create_blob(self.image_dir, [b"binary data"], "config")
        self.oci_image = OCIImage(self.image_dir)
        self.blob = Blob(self.oci_image, self.descriptor)

    def tearDown(self):
        shutil.rmtree(self.image_dir)

    def test___eq__(self):
        tests: list[tuple[Blob | str, bool]] = [
            ("an object", False),
            (Blob(self.oci_image, self.descriptor.copy()), True),
            (
                Blob(
                    self.oci_image,
                    {
                        "mediaType": self.descriptor["mediaType"],
                        "digest": self.descriptor["digest"] + "1",
                        "size": self.descriptor["size"],
                    },
                ),
                False,
            ),
            (
                Blob(
                    self.oci_image,
                    {
                        "mediaType": self.descriptor["mediaType"],
                        "digest": self.descriptor["digest"],
                        "size": self.descriptor["size"],
                        "annotations": {"type": "build"},
                    },
                ),
                False,
            ),
        ]
        for other_blob, expected in tests:
            eq = self.blob == other_blob
            self.assertEqual(expected, eq)

    def test_raw_content(self):
        content = self.blob.raw_content
        self.assertTrue(isinstance(content, bytes))
        self.assertEqual(id(content), id(self.blob.raw_content))

    def test_to_python(self):
        obj = self.blob.to_python
        self.assertTrue(isinstance(obj, bytes))
        self.assertEqual(id(obj), id(self.blob.raw_content))

    def test_delete(self):
        self.blob.delete()
        self.assertFalse(self.blob.path.exists())

    def test_save_content_has_not_been_read(self):
        blob = Blob(self.oci_image, self.descriptor)
        new_blob = blob.save()
        self.assertEqual(id(blob), id(new_blob))

    def test_save_content_is_updated(self):
        self.blob.raw_content = b"ab"
        new_blob = self.blob.save()
        self.assertNotEqual(id(self.blob), id(new_blob))
        self.assertEqual(b"ab", new_blob.path.read_bytes())
        self.assertEqual(self.blob.descriptor["mediaType"], new_blob.descriptor["mediaType"])
        self.assertNotEqual(self.blob.descriptor["digest"], new_blob.descriptor["digest"])
        self.assertNotEqual(self.blob.descriptor["size"], new_blob.descriptor["size"])

    def test_save_content_is_not_updated(self):
        new_blob = self.blob.save()
        self.assertEqual(id(self.blob), id(new_blob))
        self.assertEqual(self.blob.descriptor["mediaType"], new_blob.descriptor["mediaType"])
        self.assertEqual(self.blob.descriptor["digest"], new_blob.descriptor["digest"])
        self.assertEqual(self.blob.descriptor["size"], new_blob.descriptor["size"])


class TestManifest(unittest.TestCase):
    """Test Manifest blob class"""

    def setUp(self):
        self.oci_image_path = tempfile.mkdtemp(prefix="test_manifest-")
        create_local_oci_image(self.oci_image_path, [[b"123"]])
        oci_image = OCIImage(self.oci_image_path)
        self.manifest = oci_image.index.manifests()[0]

    def tearDown(self):
        shutil.rmtree(self.oci_image_path)

    def test_save_when_no_change_to_both_config_and_layers(self):
        # Save directly without any change to config or layers
        new_manifest = self.manifest.save()
        self.assertEqual(new_manifest, self.manifest)
        self.assertEqual(id(new_manifest), id(self.manifest))

    def test_save_when_config_is_updated(self):
        self.manifest.config.to_python["architecture"] = "amd64"
        new_manifest = self.manifest.save()
        self.assertNotEqual(id(new_manifest), id(self.manifest))
        self.assertEqual(new_manifest.config.to_python["architecture"], "amd64")

    def test_save_when_layer_is_changed(self):
        layer = self.manifest.layers[0]
        layer.raw_content += b"new binary data"
        new_manifest = self.manifest.save()
        self.assertNotEqual(new_manifest, self.manifest)
        self.assertNotEqual(id(new_manifest), id(self.manifest))
        self.assertEqual(new_manifest.layers[0].raw_content, layer.raw_content)

    def test_save_layer_without_blob_file(self):
        self.manifest.layers[0].path.unlink()
        with self.assertRaisesRegex(ValueError, expected_regex=""):
            self.manifest.save()


class TestIndex(unittest.TestCase):

    def setUp(self):
        self.oci_image_path = tempfile.mkdtemp(prefix="test-index-")
        create_local_oci_image(self.oci_image_path, [[b"123"]])
        self.oci_image = OCIImage(self.oci_image_path)

    def tearDown(self):
        shutil.rmtree(self.oci_image_path)

    def test_get_manfiests(self):
        manifests = self.oci_image.index.manifests()
        self.assertEqual(len(manifests), 1)
        self.assertTrue(manifests[0].path.exists())

        manifests_2 = self.oci_image.index.manifests()
        self.assertEqual(id(manifests), id(manifests_2))

    def test_save(self):
        manifest = self.oci_image.index.manifests()[0]
        manifest.config.to_python["architecture"] = "amd64"
        self.oci_image.index.save()

        new_manifest = self.oci_image.index.manifests()[0]
        self.assertNotEqual(manifest.descriptor["digest"], new_manifest.descriptor["digest"])
        self.assertEqual(new_manifest.config.to_python["architecture"], "amd64")
