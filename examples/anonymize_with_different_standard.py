import copy

from pydicom import dcmread
from pydicom.data import get_testdata_file

from dicomanonymizer import anonymize_dataset
from dicomanonymizer.simpledicomanonymizer import initialize_actions


def initialize_actions_2026c():
    return initialize_actions("dicomfields_2026c")


def main():
    original_ds = dcmread(get_testdata_file("CT_small.dcm"))
    data_ds = copy.deepcopy(original_ds)
    anonymize_dataset(
        data_ds, delete_private_tags=True, base_rules_gen=initialize_actions_2026c
    )  # Anonymization is done in-place
    print("Examples of original -> anonymized values:")
    for tt in ["PatientName", "PatientID", "StudyDate"]:
        print(f"  {tt}: '{original_ds[tt].value}' -> '{data_ds[tt].value}'")


if __name__ == "__main__":
    main()
