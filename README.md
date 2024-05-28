# MaiBee

MaiBee is a web browser extension for Firefox designed to detect and analyse suspicious ads on web pages. It provides users with the ability to manage and visualise detected adURLs, export results, and customise their browsing experience.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Third-Party Licenses](#third-party-licenses)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Pop-up Menu**: Activate or deactivate the extension’s functionality.
  - **BEES**: Start the ad detection on the current tab.
  - **REMOVE BEES**: Stop the ad detection on the current tab.
  - **BEES in All Tabs**: Start the ad detection on all open tabs.
- **Options Page**: Visualize collected data and manage detected URLs.
  - **Clear Detected URLs**: Remove detected URLs from the browser's local storage.
  - **Export Results to JSON**: Download a JSON file with analysis results.
  - **Download Shady URLs**: Download a text file with detected shady URLs.
- **Background Script**: Continuously detects ads using EasyList.
- **Content Scripts**: Detect and modify ad elements on web pages.

## Installation

1. Clone this repository:
   ```sh
   git clone https://github.com/mhuergae/MaiBee.git
2. If you want to retrieve AbuseIPDB information as part of the results, change line 195 of options.js and add you API key.
3. Open Firefox and navigate to `about:debugging`.
4. Click on "This Firefox" (or "This Nightly").
5. Click "Load Temporary Add-on" and select the `manifest.json` file from the `web_extension` directory.

## Usage

Open the MaiBee extension by clicking on its icon in the browser toolbar.

Use the pop-up menu to control the extension:

- Click **BEES** to start ad detection on the current tab.
- Click **REMOVE BEES** to stop ad detection on the current tab.
- Click **BEES in All Tabs** to start ad detection on all open tabs.

Access the options page by navigating to `about:addons`, clicking on "Extensions", selecting "MaiBee", and then clicking on "Options". Here you can:

- Clear detected URLs.
- Export results to JSON.
- Download shady URLs as a text file.

## Third-Party Licenses

This project includes third-party content that is licensed under different terms. For more details, see the [Third-Party Licenses](third-party-licenses.md) file.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any changes or improvements.

## License

This project is licensed under the GNU General Public License v3.0 (GPLv3). See the `LICENSE` file for more details.

