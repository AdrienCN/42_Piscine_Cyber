import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from pathlib import Path
import time
import argparse

class Scrapper:
    def __init__(self, base_url="", max_lvl=5, path="./data"):

        self.base_url = urlparse(base_url)
        self.max_lvl = max_lvl
        self.visited_url = set()
        self.stored_img = set()
        self.extensions = [".jpg", ".jpeg", ".png", ".gif", ".bmp"]
        self.storage_path = path
        return

    def scrap_site(self, cur_url="", cur_lvl=1):

        # Recursive base condition
        # - Check if website has already been scrapped to avoid duplicates
        # - Stop scrapping if maximum scrapping lvl has been reach.
        if cur_url in self.visited_url:
            return
        if cur_lvl > self.max_lvl:
            return

        self.visited_url.add(cur_url)
        try:
            # 1 - GET HTML HTTP PAGE
            # 2 - Convert HTML HTTP to parseable Text HTML
            # 3 - Download all img of current webpage
            # 4 - Find all hyperlink and loop throug them
            #     For each link, recursively repeat the scrapping
            response = requests.get(cur_url)
            soup = BeautifulSoup(response.text, "html.parser")
            self.scrap_img(soup, cur_url, cur_lvl)

            links = soup.find_all("a", href=True)
            for link in links:
                link_url = urljoin(cur_url, link["href"])
                parsed_url = urlparse(link_url)
                # Check that links have same domain name to avoid scrapping external website.
                if (self.base_url.netloc == parsed_url.netloc) \
                    or ('www.' + self.base_url.netloc == parsed_url.netloc):
                    self.scrap_site(link_url, cur_lvl + 1)  # Recursive Call

        except Exception as e:
            print(f"Spider: Error: Failed  to scrap {cur_url}\nErr:{e}")
        return

    def scrap_img(self, soup, cur_url, cur_lvl):

        # 1 - Find all image on the website with a source
        # 2 - Store them in the default ("./data") or custom PATH
        img_with_src = soup.find_all("img", src=True)
        for img_itm in img_with_src:
            img_url = urljoin(cur_url, img_itm["src"])
            img_name = Path(img_url).name
            if (img_name not in self.stored_img) and (Path(img_url).suffix in self.extensions):
                self.download_img(img_url, img_name, cur_lvl)
        return

    def download_img(self, img_url, img_name, cur_lvl):

        # 1 - Open connection with website to download the image
        # 2 - If successful, create directory and save imgs there
        try:
            response = requests.get(img_url, stream=True)
            if response.status_code == 200:

                folder_path = f'{self.storage_path}/lvl{cur_lvl}/'
                if not os.path.exists(folder_path):  # Create storage folder if it does not exist
                    os.makedirs(folder_path)
                filepath = os.path.join(folder_path, img_name)

                with open(filepath, "wb") as file:
                    for chunk in response.iter_content(1024):
                        file.write(chunk)
                self.stored_img.add(img_name)  # Add img to the list of dwnld img to avoir duplicates
        except Exception as e:
            print(f"Spider: Error: Failed to get content from {img_url}\n Err: {e}")
        return


def main():
    start_time = time.time()

    parser = argparse.ArgumentParser(
                        prog="spider",
                        usage="./spider [-r -l [N] -p] url\nex: ./spider http://www.rando_suisse.ch/fr",
                        description="Download all images from a given URL")
    parser.add_argument("-r", action="store_false")
    parser.add_argument("-l", metavar="level", type=int, choices=[1, 2, 3, 4, 5], default="5")
    parser.add_argument("-p", metavar="path", type=str, default="./data/")
    parser.add_argument('url', type=str)

    args = parser.parse_args()
    scrapper = Scrapper(base_url=args.url, max_lvl=args.l, path=args.p)
    scrapper.scrap_site(args.url)
    print(f"Total url: {len(scrapper.visited_url)}")
    print(f"Total image: {len(scrapper.stored_img)}")
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Time elapsed: {elapsed_time:.2f} seconds")

    return


if __name__ == "__main__":
    main()