# Copyright 2020 Espressif Systems (Shanghai) PTE LTD
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import regex
import csv
from rmaker_admin_lib.constants import TAG_DYNAMIC_REGEX, TAG_REGEX, TAG_DYNAMIC_SEPARATOR, COLON, COMMA, EMPTY_STRING
from rmaker_admin_lib.logger import log


class CsvValidator:
    """A class that provides validation functionality for tags and the CSV files that contain Node Registration Details."""

    def __init__(self, filename: str):
        """
        Constructor.

        Args:
         - filename (str): The filename of the CSV file.

        Raises:
         - Exception: If the CSV file could not be opened.
        """
        self._filename = filename
        try:
            with open(self._filename) as csv_file:
                reader = csv.reader(csv_file)
                self._headers = next(reader)
        except Exception as e:
            log.error(f"Error reading CSV file: {e}")

    def _parse_col_names_from_tags(self, tags: str) -> list:
        """
        Extracts column names referenced by the tags args.

        Args:
         - tags (str): The tags args used by admin.

        Returns:
         - List[str]: A list of strings containing the extracted column names.
        """
        # Get List of dynamic tag references
        col_names = []
        for tag in tags.split(COMMA):
            if tag != EMPTY_STRING and regex.match(TAG_DYNAMIC_REGEX, tag):
                _, _, col_name = tag.partition(TAG_DYNAMIC_SEPARATOR)
                if col_name != EMPTY_STRING:
                    col_names.append(col_name)
        return col_names

    def _trim_tags_and_validate(self, tags: str):
        """
        Trims the tags(tag name and value) of leading and trailing whitespaces
        Also Validates the tags args passed by the admin and checks if they are valid.

        Args:
         - tags(str): The tags passed as args which are to be trimmed

         Returns:
          - str|bool: If tags are invalid, returns false, otherwise returns trimmed tags
        """
        tags_array = tags.split(COMMA)
        tagsTrimmed = []

        if len(tags_array) < 1:
            log.error("No tags passed to trim, recheck input args")
            return False

        for tag in tags_array:
            if regex.match(TAG_DYNAMIC_REGEX, tag):
                separator = TAG_DYNAMIC_SEPARATOR
            elif regex.match(TAG_REGEX, tag):
                separator = COLON
            else:
                return False
            tag_name, separator, tag_value = tag.partition(separator)
            tagsTrimmed.append(tag_name.strip() +
                               separator + tag_value.strip())
        return COMMA.join(tagsTrimmed)

    def are_valid(self, tags: str):
        """
        Validates the tags passed against the inputFile(CSV).

        Args:
         - tags (str): The tags to validate against the inputFile(CSV).

        Returns:
         - False if invalid
         - Valid/Trimmed tags if valid

        The conditions validated are:
        - The passed tags are valid.
        - The CSV contains the required tag references.
        """
        # Trim the tag names and values before proceeding.
        # Also check if the tags formats are valid or not.
        tags = self._trim_tags_and_validate(tags)
        if not tags:
            log.error(
                "Invalid tags specified by user. Check tags format. Exiting.")
            return False

        # Get the required column names from the dynamic tag references.
        col_names = self._parse_col_names_from_tags(tags)

        # All the required column names must be present in the dataFrame columns.
        if bool(set(col_names) - set(self._headers)):
            log.error(
                "Invalid tags specified by user. Check whether the tags are referencing the proper column names. Exiting.")
            return False

        return tags
