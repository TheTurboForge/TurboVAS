/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import styled from 'styled-components';
import TurboVASLogo from 'web/components/img/TurboVASLogo';

const StyledLogo = styled(TurboVASLogo)`
  width: 300px;
  height: 72px;
  color: #111111;
  font-size: 42px;
  justify-content: flex-start;
`;

const LoginLogo = () => {
  return <StyledLogo data-testid="login-logo" />;
};

export default LoginLogo;
