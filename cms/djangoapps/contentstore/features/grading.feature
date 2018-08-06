@shard_1
Feature: CMS.Course Grading
    As a course author, I want to be able to configure how my course is graded

    # Note that "7" is a special weight because it revealed rounding errors (STUD-826).
    Scenario: Users can set weight to Assignment types
        Given I have opened a new course in Studio
        And I am viewing the grading settings
        When I add a new assignment type "New Type"
        And I set the assignment weight to "7"
        And I press the "Save" notification button
        Then the assignment weight is displayed as "7"
        And I reload the page
        Then the assignment weight is displayed as "7"

    Scenario: Users can delete Assignment types
        Given I have populated a new course in Studio
        And I am viewing the grading settings
        When I delete the assignment type "Homework"
        And I press the "Save" notification button
        And I go back to the main course page
        Then I do not see the assignment name "Homework"

    Scenario: Users can add Assignment types
        Given I have populated a new course in Studio
        And I am viewing the grading settings
        When I add a new assignment type "New Type"
        And I press the "Save" notification button
        And I go back to the main course page
        Then I do see the assignment name "New Type"

    Scenario: User cannot save invalid settings
        Given I have populated a new course in Studio
        And I am viewing the grading settings
        When I change assignment type "Homework" to ""
        Then the save notification button is disabled

    # IE and Safari cannot type in grade range name
    @skip_internetexplorer
    @skip_safari
    Scenario: User can edit grading range names
        Given I have populated a new course in Studio
        And I am viewing the grading settings
        When I change the highest grade range to "Good"
        And I press the "Save" notification button
        And I reload the page
        Then I see the highest grade range is "Good"

    Scenario: User cannot edit failing grade range name
        Given I have populated a new course in Studio
        And I am viewing the grading settings
        Then I cannot edit the "Fail" grade range

    Scenario: User can set a grace period greater than one day
        Given I have populated a new course in Studio
        And I am viewing the grading settings
        When I change the grace period to "48:00"
        And I press the "Save" notification button
        And I reload the page
        Then I see the grace period is "48:00"

    Scenario: Grace periods of more than 59 minutes are wrapped to the correct time
        Given I have populated a new course in Studio
        And I am viewing the grading settings
        When I change the grace period to "01:99"
        And I press the "Save" notification button
        And I reload the page
        Then I see the grace period is "02:39"
