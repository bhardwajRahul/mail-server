/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use crate::transformers::osb::OsbToken;

use super::{BayesModel, TokenHash};

impl BayesModel {
    pub fn train<T>(&mut self, tokens: T, is_spam: bool)
    where
        T: IntoIterator<Item = OsbToken<TokenHash>>,
    {
        if is_spam {
            self.spam_learns += 1;
        } else {
            self.ham_learns += 1;
        }

        for token in tokens {
            let hs = self.weights.entry(token.inner).or_default();
            if is_spam {
                hs.spam += 1;
            } else {
                hs.ham += 1;
            }
        }
    }

    pub fn untrain<T>(&mut self, tokens: T, is_spam: bool)
    where
        T: IntoIterator<Item = OsbToken<TokenHash>>,
    {
        if is_spam {
            self.spam_learns -= 1;
        } else {
            self.ham_learns -= 1;
        }

        for token in tokens {
            let hs = self.weights.entry(token.inner).or_default();
            if is_spam {
                hs.spam -= 1;
            } else {
                hs.ham -= 1;
            }
        }
    }
}