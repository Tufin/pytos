Approve SecureChange ticket
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following example shows a SecureChange ticket template based on XML format. The template must be align with the
first step in the workflow. The following example show the mandatory tags and one Access Request field.
::
	<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
	<ticket>
		<subject></subject>
		<domain_name>Default</domain_name>
		<priority>Normal</priority>
		<workflow>
			<name>Workflow Name</name>
		</workflow>
		<steps>
			<step>
				<name></name>
				<tasks>
					<task>
						<fields>
							<field xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="multi_access_request">
								<name>Submit Firewall Access</name>
							</field>
						</fields>
					</task>
				</tasks>
			</step>
		</steps>
		<comments/>
	</ticket>
