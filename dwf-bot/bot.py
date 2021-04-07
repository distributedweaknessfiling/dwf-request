#!/usr/bin/env python3

import requests
import os
import re
import tempfile
import git
import json
import datetime
import time

repo_name = os.environ['GH_REPO']
issues_url = "https://api.github.com/repos/%s/issues" % repo_name
repo_url = "https://github.com/%s.git" % repo_name
username = os.environ['GH_USERNAME']

class Issue:
	def __init__(self, details):

		self.raw_data = details
		self.lines = details['body'].splitlines()
		self.comments_url = details['comments_url']
		self.events_url = details['events_url']
		self.url = details['url']
		self.title = details['title']
		self.id = details['number'];	
		self.creator = details['user']['login']
		self.auth = (username, os.environ['GH_TOKEN'])

	def get_dwf_id(self):
		# We are going to only trust the comment from <username> for this
		# ID. It's the most trustworthy ID

		comments = self.get_comments()
		comments.reverse()
		for i in comments:
			if i['user']['login'] == username:
				if i['body'].startswith('This issue has been assigned'):
					match = re.search('((CVE|CAN)-\d{4}-\d+)', i['body'])	
					dwf_id = match.groups()[0]
					return dwf_id	
		return None

	def get_events(self):

		events = []
		page = 0
		while(True):
			params = {
					'per_page': 100,
					'page': page
			}
			resp = requests.get(self.events_url, auth=self.auth, params=params)
			resp.raise_for_status()
			if len(resp.json()) == 0:
				break
			else:
				page = page + 1
				events.extend(resp.json())

		return events

	def get_comments(self):
		comments = []
		page = 0
		while(True):
			params = {
					'per_page': 100,
					'page': page
			}
			resp = requests.get(self.comments_url, auth=self.auth, params=params)
			resp.raise_for_status()
			if len(resp.json()) == 0:
				break
			else:
				page = page + 1
				comments.extend(resp.json())

		return comments

	def who_approved(self):
		events = self.get_events()
		# We should reverse the list as we want to figure out who gave the last approval
		events.reverse()
		for i in events:
			# I'm pretty sure we need better logic here
			if i['event'] == 'labeled' and i['label']['name'] == 'approved':
				approver = i['actor']['login']
				approver_id = i['actor']['id']
				return "%s:%s" % (approver, approver_id)

	def get_reporter(self):
		data = self.get_dwf_json()
		the_reporter = "%s:%s" % (data['reporter'], data['reporter_id'])
		return the_reporter

	def get_dwf_json(self):
		dwf_json = ""
		found_json = False

		for l in self.lines:
			if l == "--- DWF JSON ---":
				found_json = not found_json
			elif found_json is True:
				dwf_json = dwf_json + l

		dwf_data = json.loads(dwf_json)
		return dwf_data

	def add_comment(self, comment):
		body = {
			"body": comment
		}

		headers = {
			"accept": "application/json"
		}

		resp = requests.post(self.comments_url, json=body, auth=self.auth, headers=headers)
		resp.raise_for_status()

	def can_to_dwf(self):
		can_id = self.get_dwf_id()
		# Make sure the ID starts with CAN
		if not can_id.startswith('CAN-'):
			return None

		# Get the path to the file
		year = can_id.split('-')[1]
		id_str = can_id.split('-')[2]
		dwf_id = "CVE-%s-%s" % (year, id_str)

		self.title = self.title.replace(can_id, dwf_id)		
		body = {
			"title": self.title,
			"state": "closed"
		}
		headers = {
			"accept": "application/json"
		}
		resp = requests.post(self.url, json=body, auth=self.auth, headers=headers)
		resp.raise_for_status()

	def assign_dwf(self, dwf_id, approved_user = False):

		# Add a comment to the issue
		self.add_comment("This issue has been assigned %s" % dwf_id)

                # Modify the title and labels
		body = {
			"title": "[%s] %s" % (dwf_id, self.title),
			"labels": ["assigned"]
		}

		headers = {
			"accept": "application/json"
		}

		if approved_user:
			body["state"] = "closed"
		else:
			# CAN IDs get the candidate label
			body["labels"] = ["assigned", "candidate"]

		resp = requests.post(self.url, json=body, auth=self.auth, headers=headers)
		resp.raise_for_status()

def get_new_issues():
	auth = (username, os.environ['GH_TOKEN'])
	params = {
			'accept': "application/vnd.github.v3+json",
			'labels': 'new,check',
			'state': 'open'
	}

	# XXX Get the repo from the environment or something
	resp = requests.get(issues_url, auth=auth, params=params)
	resp.raise_for_status()

	issues = resp.json()

	to_return = []
	for i in issues:
		to_return.append(Issue(i))

	return to_return

def get_approved_can_issues():
	auth = (username, os.environ['GH_TOKEN'])
	params = {
			'accept': "application/vnd.github.v3+json",
			'labels': 'approved',
			'state': 'open'
	}

	# XXX Get the repo from the environment or something
	resp = requests.get(issues_url, auth=auth, params=params)
	resp.raise_for_status()

	issues = resp.json()

	to_return = []
	for i in issues:
		to_return.append(Issue(i))

	return to_return

class DWFRepo:
	def __init__(self):

		self.tmpdir = tempfile.TemporaryDirectory()
		self.repo = git.Repo.clone_from(repo_url, self.tmpdir.name)
		allow_list_files = os.path.join(self.tmpdir.name, "allowlist.json")
		with open(allow_list_files) as json_file:
			self.allowed_users = json.loads(json_file.read())

	def approved_user(self, user):
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

	def generate_description(self, issue_data):

		#In [vendor name] [product name] version [version info] a
		#[vulnerability type] exists in the [affected component] that can be
		#attacked via [attack vector] resulting in [impact of exploitation].

		the_string = f'''In {issue_data["vendor_name"]} {issue_data["product name"]} version {issue_data["version info"]} a
				{issue_data["vulnerability type"]} exists in the {issue_data["affected component"]} that can be
				attacked via {issue_data["attack vector"]} resulting in {issue_data["impact of exploitation"]}.'''
		return the_string

	def get_dwf_json_format(self, dwf_id, issue_data):

		# This data format is beyond terrible. Apologies if you found this. I am ashamed for the author of it.
		# We will fix it someday, but not today. The initial goal is to be compatible
		c = {
			# metadata
			# Only two values possible? This might need to be a function if not.
			"data_type": "CVE" if dwf_id.startswith("CVE") else "CAN",
			"data_format": "MITRE",
			"data_version": "4.0",
			"CVE_data_meta": {
				"ASSIGNER": "dwf",
				# CAN ID
				"ID": dwf_id,
				"STATE": "PUBLIC",
			},
			# affected
			"affects": {
				"vendor": {
					"vendor_data": [{
						"vendor_name": issue_data["vendor_name"],
						"product": {
							"product_data": [{}],
							"product_name": issue_data["product_name"],
							"version": {
								"version_data": [{
									# ಠ_ಠ
									"version_value": issue_data["product_version"],
									}],
								},
							},
	
						}],
					}
				},
			# problem
			"problemtype": {
				"problemtype_data": [{
					"description": [{
						"lang": "eng",
						"value": issue_data["vulnerability_type"],
					}],
				}],
				},
	
			# references
			"references": {
				# This will be a list comprehension, we can have multiple references
				"reference_data": [{
					"url": i,
					"refsource": "MISC",
					"name": i
					} for i in issue_data["references"]] # Don't miss the end of the comprehension
				},
			# description
			"description": {
				"description_data": [{
					"lang": "eng",
					"value": self.generate_description(issue_data),
					}],
				},
			# DWF namespace
			# If there is any new data to add, do it here. The previous fields should be treated as legacy
			"dwf": issue_data,
			}
		return c

def main():

	start_time = datetime.datetime.now()

	new_issues = get_new_issues()
	can_issues = get_approved_can_issues()

	if len(new_issues) > 0 or len(can_issues) > 0:

		# Only touch the repo if we have work to do
		dwf_repo = DWFRepo()

		# Look for new issues
		for i in new_issues:

			if re.search('(CVE|CAN)-\d{4}-\d+', i.title):
				# There shouldn't be a CVE/CAN ID in the title, bail on this issue
				print("Found an ID in the title for issue %s" % i.id)
				continue

			if (i.creator != username):
				print("Issue %s is not created by %s" % (i.id, username))
				continue

			print("Updating issue %s" % i.id)
			dwf_id = dwf_repo.add_dwf(i)
			i.assign_dwf(dwf_id, dwf_repo.approved_user(i.get_reporter()))

		# Now look for approved CAN issues
		for i in can_issues:
			approver = i.who_approved()
			if dwf_repo.approved_user(approver):
				# Flip this to a DWF
				dwf_repo.can_to_dwf(i)
				i.can_to_dwf()
			else:
				print("%s is unapproved for %s" % (approver, i.id))

		dwf_repo.close()

	stop_time = datetime.datetime.now()
	total_time = stop_time - start_time
	total_seconds = total_time.total_seconds()

	if total_seconds < 10:
		# Things get weird if we die too early wtih docker-compose
		time.sleep(10 - total_seconds)
	
if __name__ == "__main__":
	main()
