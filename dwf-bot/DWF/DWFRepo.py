
import tempfile
import git
import os
import json
import datetime

class DWFRepo:
	def __init__(self, repo_url, testing=False):

		self.testing = testing
		self.tmpdir = tempfile.TemporaryDirectory()
		self.repo = git.Repo.clone_from(repo_url, self.tmpdir.name)
		allow_list_files = os.path.join(self.tmpdir.name, "allowlist.json")
		with open(allow_list_files) as json_file:
			self.allowed_users = json.loads(json_file.read())

	def approved_user(self, user='', user_name=None, user_id=None):
		if user_name is not None and user_id is not None:
			user="%s:%s" % (user_name, user_id)
		return user in self.allowed_users

	def can_to_dwf(self, dwf_issue):

		can_id = dwf_issue.get_dwf_id()
		# Make sure the ID starts with CAN
		if not can_id.startswith('CAN-'):
			return None

		# Get the path to the file
		year = can_id.split('-')[1]
		id_str = can_id.split('-')[2]
		namespace = "%sxxx" % id_str[0:-3]
		dwf_id = "CVE-%s-%s" % (year, id_str)
		filename = "%s.json" % (dwf_id)

		can_file = os.path.join(year, namespace, filename)
		git_file = os.path.join(self.repo.working_dir, can_file)
		
		# Open the file
		with open(git_file) as json_file:
				# Read the json
				can_data = json.loads(json_file.read())

		# Swap the CAN to CVE
		can_data['data_type'] = 'CVE'
		can_data['CVE_data_meta']['ID'] = dwf_id

		dwf_json = json.dumps(can_data, indent=2)
		dwf_json = dwf_json + "\n"
		# save the json
		with open(git_file, 'w') as json_file:
			json_file.write(dwf_json)

		# Commit the file
		self.repo.index.add(can_file)
		self.repo.index.commit("Promoted to %s for #%s" % (dwf_id, dwf_issue.id))
		self.push()
		return dwf_id

	def add_dwf(self, dwf_issue):

		dwf_data = dwf_issue.get_dwf_json()

		# Check the allowlist
		reporter = dwf_issue.get_reporter()

		approved_user = self.approved_user(reporter)

		(dwf_id, dwf_path) = self.get_next_dwf_path(approved_user)

		new_dwf_data = self.get_dwf_json_format(dwf_id, dwf_data)
		dwf_json = json.dumps(new_dwf_data, indent=2)
		dwf_json = dwf_json + "\n"

		with open(os.path.join(self.repo.working_dir, dwf_path), 'w') as json_file:
			json_file.write(dwf_json)

		self.repo.index.add(dwf_path)
		self.repo.index.commit("Add %s for #%s" % (dwf_id, dwf_issue.id))
		self.push()

		return dwf_id

	def push(self):
		# Don't push if we're testing
		if self.testing:
			pass
		else:
			self.repo.remotes.origin.push()

	def close(self):
		self.tmpdir.cleanup()

	def get_next_dwf_path(self, approved_user = False):
		# Returns the next DWF ID and the path where it should go
		# This needs a lot more intelligence, but it'll be OK for the first pass. There are plenty of integers
		dwf_path = None
		the_dwf = None

		# Get the current year
		year = str(datetime.datetime.now().year)
		year_dir = os.path.join(self.tmpdir.name, year)

		# Make sure the year directory exists
		if not os.path.exists(year_dir):
			os.mkdir(year_dir)

		# Start looking in directory 1000xxx
		# If that's full, move to 1001xxx
		# We will consider our namespace everything up to 1999999
		for i in range(1000, 2000, 1):
			block_dir = "%sxxx" % i
			block_path = os.path.join(year_dir, block_dir)
			if not os.path.exists(block_path):
				# This is a new path with no files
				os.mkdir(block_path)
				the_dwf = "CVE-%s-%s000" % (year, i)
				dwf_path = os.path.join(block_path, "%s.json" % the_dwf)
				if not approved_user:
					the_dwf = "CAN-%s-%s000" % (year, i)
				break

			else:
				
				files = os.listdir(block_path)
				files.sort()
				last_file = files[-1]
				id_num = int(last_file.split('.')[0].split('-')[2])
				next_id = id_num + 1
				if next_id % 1000 == 0:
					# It's time to roll over, we'll pick up the ID in the next loop
					continue

				the_dwf = "CVE-%s-%s" % (year, next_id)
				dwf_path = os.path.join(block_path, "%s.json" % the_dwf)
				if not approved_user:
					the_dwf = "CAN-%s-%s" % (year, next_id)
				break

		return (the_dwf, dwf_path)

	def get_dwf_json_format(self, dwf_id, issue_data):

		# This data format is beyond terrible. Apologies if you found this. I am ashamed for the author of it.
		# We will fix it someday, but not today. The initial goal is to be compatible

		c = {};

		# DWF namespace. We want this at the top because it's easy to read
		# If there is any new data to add, do it here. The previous fields should be treated as legacy
		c["dwf"] = issue_data


		# metadata
			# Or CAN
		if dwf_id.startswith("CVE"):
			c["data_type"] = "CVE"
		else:
			c["data_type"] = "CAN"
		c["data_format"] = "MITRE"
		c["data_version"] = "4.0"
		c["CVE_data_meta"] = {}
		c["CVE_data_meta"]["ASSIGNER"] = "dwf"
			# CAN ID
		c["CVE_data_meta"]["ID"] = dwf_id
		c["CVE_data_meta"]["STATE"] = "PUBLIC"

		# affected
		c["affects"] = {};
		c["affects"]["vendor"] = {}
		c["affects"]["vendor"]["vendor_data"] = []
		c["affects"]["vendor"]["vendor_data"].append({})
		c["affects"]["vendor"]["vendor_data"][0]["vendor_name"] = issue_data["vendor_name"]
		c["affects"]["vendor"]["vendor_data"][0]["product"] = {}
		c["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"] = []
		c["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"].append({})
		c["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"][0]["product_name"] = issue_data["product_name"]
		c["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"][0]["version"] = {}
		c["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"][0]["version"]["version_data"] = []
		c["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"][0]["version"]["version_data"].append({})
		# ಠ_ಠ
		c["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"][0]["version"]["version_data"][0]["version_value"] = issue_data["product_version"]

		# problem
		c["problemtype"] = {}
		c["problemtype"]["problemtype_data"] = []
		c["problemtype"]["problemtype_data"].append({})
		c["problemtype"]["problemtype_data"][0]["description"] = []
		c["problemtype"]["problemtype_data"][0]["description"].append({})
		c["problemtype"]["problemtype_data"][0]["description"][0]["lang"] = "eng"
		c["problemtype"]["problemtype_data"][0]["description"][0]["value"] = issue_data["vulnerability_type"]

		# references
		c["references"] = {}
		c["references"]["reference_data"] = []
		# This will be a loop, we can have multiple references
		for i in issue_data["references"]:
			c["references"]["reference_data"].append({})
			c["references"]["reference_data"][-1]["url"] = i
			c["references"]["reference_data"][-1]["refsource"] = "MISC"
			c["references"]["reference_data"][-1]["name"] = i

		# description
		c["description"] = {}
		c["description"]["description_data"] = []
		c["description"]["description_data"].append({})
		c["description"]["description_data"][0]["lang"] = "eng"
		c["description"]["description_data"][0]["value"] = issue_data["description"]

		return c

