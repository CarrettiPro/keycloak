/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.testsuite.ui.account2;

import org.jboss.arquillian.graphene.page.Page;
import org.junit.Ignore;
import org.junit.Test;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.testsuite.ui.account2.page.ForbiddenPage;
import org.keycloak.testsuite.ui.account2.page.PersonalInfoPage;
import org.keycloak.testsuite.ui.account2.page.SigningInPage;
import org.keycloak.testsuite.ui.account2.page.WelcomeScreen;

import java.util.List;
import java.util.stream.Collectors;

import static org.keycloak.models.AccountRoles.MANAGE_ACCOUNT;
import static org.keycloak.models.Constants.ACCOUNT_MANAGEMENT_CLIENT_ID;
import static org.keycloak.testsuite.auth.page.AuthRealm.TEST;

/**
 * @author Vaclav Muzikar <vmuzikar@redhat.com>
 */
@Ignore // TODO Remove when KEYCLOAK-17366 is fixed
public class PermissionsTest extends AbstractAccountTest {
    @Page
    private WelcomeScreen welcomeScreen;

    @Page
    private PersonalInfoPage personalInfoPage;

    @Page
    private SigningInPage signingInPage;

    @Page
    private ForbiddenPage forbiddenPage;

    private static final String DEFAULT_ROLE_NAME = "default-roles-" + TEST;

    @Test
    public void manageAccountRoleRequired() {
        // remove the default role from test user ACCOUNT_MANAGEMENT_CLIENT_ID
        String accountClientId = testRealmResource().clients().findByClientId(ACCOUNT_MANAGEMENT_CLIENT_ID).get(0).getId();

        List<RoleRepresentation> rolesToRemove = testRealmResource().roles()
                .get(DEFAULT_ROLE_NAME)
                .getClientRoleComposites(accountClientId).stream()
                .filter(role -> role.getName().equals(MANAGE_ACCOUNT))
                .collect(Collectors.toList());

        testRealmResource().roles().get(DEFAULT_ROLE_NAME).deleteComposites(rolesToRemove);

        welcomeScreen.header().clickLoginBtn();
        loginToAccount();
        welcomeScreen.assertCurrent(); // no forbidden at welcome screen yet

        welcomeScreen.clickPersonalInfoLink();
        forbiddenPage.assertCurrent();

        signingInPage.navigateToUsingSidebar();
        forbiddenPage.assertCurrent();

        // still possible to sign out
        forbiddenPage.header().clickLogoutBtn();
        welcomeScreen.assertCurrent();
        welcomeScreen.header().assertLoginBtnVisible(true);
        welcomeScreen.header().assertLogoutBtnVisible(false);

        // Revert role changes
        getCleanup().addCleanup((Runnable) () -> testRealmResource().roles().get(DEFAULT_ROLE_NAME).addComposites(rolesToRemove));
    }
}
