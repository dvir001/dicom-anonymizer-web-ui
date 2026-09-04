import pydicom

from dicomanonymizer import anonymize_dataset
from dicomanonymizer.simpledicomanonymizer import (
    empty,
    initialize_actions,
    initialize_actions_2024b,
)


def test_anonymization_without_dicom_file():
    # Create a list of tags object that should contains id, type and value
    fields = [
        {  # Replaced by Anonymized
            "id": (0x0040, 0xA123),
            "type": "LO",
            "value": "Annie de la Fontaine",
        },
        {  # Replaced with empty value
            "id": (0x0008, 0x0050),
            "type": "TM",
            "value": "bar",
        },
        {  # Deleted
            "id": (0x0018, 0x4000),
            "type": "VR",
            "value": "foo",
        },
        {  # Relaced with empty value via extra anonymization rules since no tags with IS value type are anonymized by default.
            "id": (0x0020, 0x0012),
            "type": "IS",
            "value": "123",
        },
    ]

    # Create a readable dataset for pydicom
    data = pydicom.Dataset()

    # Add each field into the dataset
    for field in fields:  # sourcery skip: no-loop-in-tests
        data.add_new(field["id"], field["type"], field["value"])

    anonymize_dataset(data, extra_anonymization_rules={(0x0020, 0x0012): empty})

    assert data[(0x0040, 0xA123)].value == "ANONYMIZED"
    assert data[(0x0008, 0x0050)].value == "000000.00"
    assert (0x0018, 0x4000) not in data
    assert int(data[(0x0020, 0x0012)].value) == 0


def test_anonymization_of_ranged_tags_without_dicom_file():
    """Test the anonymization of ranged tags in a dataset without a DICOM file."""
    # Create Curve Data (50xx, xxxx) which must be deleted
    # per (0x5000, 0x0000, 0xFF00, 0x0000) rule.
    fields = [
        {  # to be deleted
            "id": (0x5011, 0x0110),  # Curve Data Descriptor
            "type": "US",
            "value": "dummy curve data descriptor 1",
        },
        {  # to be deleted
            "id": (0x5012, 0x0112),  # Coordinate Start Value
            "type": "US",
            "value": "dummy curve data descriptor 2",
        },
    ]

    # Create a readable dataset for pydicom
    data = pydicom.Dataset()

    # Add each field into the dataset
    for field in fields:  # sourcery skip: no-loop-in-tests
        data.add_new(field["id"], field["type"], field["value"])

    anon_ds = data.copy()
    anonymize_dataset(anon_ds)

    # Check that the dataset has been anonymized
    assert (0x5011, 0x0110) not in anon_ds
    assert (0x5012, 0x0112) not in anon_ds


def test_switching_dicom_versions():
    """To confirm the different behavior of annonymization beteen dicom versions of 2023 and 2024b."""
    fields = [
        {  # Replaced by Anonymized
            "id": (0x0010, 0x0020),
            "type": "LO",
            "value": "Test Patient ID",
        },
    ]

    # Create a readable dataset for pydicom
    data = pydicom.Dataset()
    data_2023 = pydicom.Dataset()
    data_2024b = pydicom.Dataset()

    for field in fields:  # sourcery skip: no-loop-in-tests
        data.add_new(field["id"], field["type"], field["value"])
        data_2023.add_new(field["id"], field["type"], field["value"])
        data_2024b.add_new(field["id"], field["type"], field["value"])

    anonymize_dataset(data, base_rules_gen=initialize_actions)
    anonymize_dataset(
        data_2023, base_rules_gen=lambda: initialize_actions("dicomfields_2023")
    )
    anonymize_dataset(data_2024b, base_rules_gen=initialize_actions_2024b)

    assert data[(0x0010, 0x0020)].value == ""  # default behavior which is DICOM 2023.
    assert data_2023[(0x0010, 0x0020)].value == ""  # same as the default.
    assert (
        data_2024b[(0x0010, 0x0020)].value == "ANONYMIZED"
    )  # 2024b differs from the default


def test_anonymization_of_vrs_not_in_dcm_example_files():
    """Tags of the confidentiality profile whose VRs do not appear in the .dcm
    example files used by test_anon.py, so they are not covered there."""
    fields = [
        {  # Replaced with b'Anonymized', action D. Type 1 in its IODs, so it
            # must keep a non-zero length value rather than be removed.
            "id": (0x0042, 0x0011),  # Encapsulated Document
            "type": "OB",
            "value": b"%PDF-1.4 payload",
        },
        {  # Replaced by ANONYMIZED, action D
            "id": (0x2100, 0x0140),  # Destination AE
            "type": "AE",
            "value": "REAL_AE_TITLE",
        },
        {  # Replaced by ANONYMIZED, action D
            "id": (0x0018, 0x9367),  # X-Ray Source ID
            "type": "UC",
            "value": "SOURCE-SERIAL-9931",
        },
        {  # Replaced by a reserved URI, action D
            "id": (0x0072, 0x0071),  # Selector UR Value
            "type": "UR",
            "value": "http://hospital.example/patient/1",
        },
        {  # Replaced by 000Y, action D. AS is a fixed 4-byte string, so the
            # generic ANONYMIZED value would be invalid for it.
            "id": (0x0072, 0x005F),  # Selector AS Value
            "type": "AS",
            "value": "045Y",
        },
        {  # Replaced with empty value, action Z
            "id": (0x3010, 0x001B),  # Device Alternate Identifier
            "type": "UC",
            "value": "DEVICE-77",
        },
    ]

    # Create a readable dataset for pydicom
    data = pydicom.Dataset()

    # Add each field into the dataset
    for field in fields:  # sourcery skip: no-loop-in-tests
        data.add_new(field["id"], field["type"], field["value"])

    anonymize_dataset(data)

    assert data[(0x0042, 0x0011)].value == b"Anonymized"
    assert data[(0x2100, 0x0140)].value == "ANONYMIZED"
    assert data[(0x0018, 0x9367)].value == "ANONYMIZED"
    assert data[(0x0072, 0x0071)].value == "http://anonymized.invalid"
    assert data[(0x0072, 0x005F)].value == "000Y"
    assert data[(0x3010, 0x001B)].value == ""


def test_anonymization_of_vrs_not_in_dcm_example_files_in_a_sequence():
    """replace_element() recurses into sequences without consulting the action
    map, so a sub-element VR missing from its VR chain used to raise even
    though the enclosing tag was handled."""
    item = pydicom.Dataset()
    item.add_new((0x0042, 0x0011), "OB", b"nested payload")

    data = pydicom.Dataset()
    # Content Sequence, action D
    data.add_new((0x0040, 0xA730), "SQ", pydicom.Sequence([item]))

    anonymize_dataset(data)

    assert data[(0x0040, 0xA730)][0][(0x0042, 0x0011)].value == b"Anonymized"


def test_anonymization_of_raw_data_element_in_a_sequence(tmp_path):
    """pydicom keeps sub-elements as RawDataElement until they are accessed,
    which is how datasets read from disk or received from a PACS arrive.
    Assigning to RawDataElement.value raises AttributeError, so empty_element()
    needs the same conversion replace_element() already does. Issue #85."""
    item = pydicom.Dataset()
    item.add_new((0x0040, 0xA123), "PN", "Annie de la Fontaine")

    data = pydicom.Dataset()
    data.file_meta = pydicom.dataset.FileMetaDataset()
    data.file_meta.TransferSyntaxUID = pydicom.uid.ExplicitVRLittleEndian
    data.file_meta.MediaStorageSOPClassUID = pydicom.uid.SecondaryCaptureImageStorage
    data.file_meta.MediaStorageSOPInstanceUID = "1.2.3.4.5"
    data.SOPClassUID = pydicom.uid.SecondaryCaptureImageStorage
    data.SOPInstanceUID = "1.2.3.4.5"
    # Verifying Observer Identification Code Sequence, action Z
    data.add_new((0x0040, 0xA088), "SQ", pydicom.Sequence([item]))

    # Round-trip through a file so the sub-element is genuinely raw
    path = tmp_path / "raw.dcm"
    pydicom.dcmwrite(path, data, enforce_file_format=True)
    reread = pydicom.dcmread(path)
    assert any(
        isinstance(e, pydicom.dataelem.RawDataElement)
        for e in reread[(0x0040, 0xA088)][0].elements()
    ), "test precondition: sub-element should still be raw"

    anonymize_dataset(reread)

    assert reread[(0x0040, 0xA088)][0][(0x0040, 0xA123)].value == ""
