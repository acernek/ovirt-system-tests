#
# Copyright oVirt Authors
# SPDX-License-Identifier: GPL-2.0-or-later
#
import logging

from selenium.webdriver.common.by import By
from .EntityListView import EntityListView

LOGGER = logging.getLogger(__name__)


class DisksListView(EntityListView):
    def __init__(self, ovirt_driver):
        super(DisksListView, self).__init__(
            ovirt_driver,
            'disks',
            ['Storage', 'Disks'],
            'MainDiskView_table_content_col0_row',
        )

    def is_new_button_enabled(self):
        return self.ovirt_driver.is_button_enabled('New')

    def is_edit_button_enabled(self):
        return self.ovirt_driver.is_button_enabled('Edit')

    def is_remove_button_enabled(self):
        return self.ovirt_driver.is_button_enabled('Remove')

    def is_move_button_enabled(self):
        return self.ovirt_driver.is_button_enabled('Move')

    def is_copy_button_enabled(self):
        return self.ovirt_driver.is_button_enabled('Copy')

    def is_upload_button_enabled(self):
        return self.ovirt_driver.is_button_enabled('Upload')

    def get_status(self, entity_name):
        names_to_ids = self.ovirt_driver.retry_if_stale(self._get_entity_names_to_ids)

        if entity_name not in names_to_ids:
            raise Exception(f'No {self.entity_type} with the name {entity_name} found')

        # find the id of the name column (column 0) and replace 1 by 10 to
        # get the id of the status column (column 10)
        name_id = names_to_ids[entity_name]
        status_id = name_id.replace("0_row", "10_row")
        status_text = self.ovirt_driver.retry_if_stale(
            lambda: self.ovirt_driver.driver.find_element(By.ID, status_id).text
        )
        return status_text

    def upload(self, image_local_path, image_name):
        LOGGER.debug(f'Upload image from local path {image_local_path}')

        self.click_menu_dropdown_button('ActionPanelView_Upload', 'Start')

        self.ovirt_driver.wait_until(
            'Upload image dialog is not displayed',
            self.ovirt_driver.is_xpath_present,
            '//*[@id="UploadImagePopupView_fileUpload"]',
        )
        self.ovirt_driver.driver.find_element(By.ID, 'UploadImagePopupView_fileUpload').send_keys(image_local_path)
        self.ovirt_driver.wait_until(
            'Upload image dialog is not displayed',
            self.ovirt_driver.is_xpath_displayed,
            '//*[@id="VmDiskPopupWidget_alias"]',
        )
        self.ovirt_driver.driver.find_element(By.ID, 'VmDiskPopupWidget_alias').send_keys(image_name)

        self.ovirt_driver.id_wait_and_click('OK button is not displayed and enabled', 'UploadImagePopupView_Ok')
        self.ovirt_driver.wait_long_until(
            'Waiting for disk to appear in disk list',
            lambda: image_name in self.get_entities(),
        )
