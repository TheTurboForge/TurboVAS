/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {render} from 'web/testing';
import Image from 'web/components/img/Image';

describe('Image tests', () => {
  test('should render image with attributes', () => {
    const {element} = render(<Image alt="TurboVAS" src="login-label.svg" />);

    expect(element).toHaveAttribute('alt', 'TurboVAS');
    expect(element).toHaveAttribute('src', '/img/login-label.svg');
  });
});
