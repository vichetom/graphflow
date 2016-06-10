#The MIT License (MIT)
#
#Copyright (c) 2015 Andre Queiroz
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in
#all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#THE SOFTWARE.
#
# Holt-Winters algorithms to forecasting
# Coded in Python 2 by: Andre Queiroz
# Description: This module contains three exponential smoothing algorithms. They are Holt's linear trend method and Holt-Winters seasonal methods (additive and multiplicative).
# References:
#  Hyndman, R. J.; Athanasopoulos, G. (2013) Forecasting: principles and practice. http://otexts.com/fpp/. Accessed on 07/03/2013.
#  Byrd, R. H.; Lu, P.; Nocedal, J. A Limited Memory Algorithm for Bound Constrained Optimization, (1995), SIAM Journal on Scientific and Statistical Computing, 16, 5, pp. 1190-1208.

from scipy.optimize import fmin_l_bfgs_b
from collections import deque


def HWT(x, m, m2, forecast, alpha=None, beta=None, gamma=None, delta=None,
        initial_values_optimization=[0.5, 0.5, 0.5, 0.5]):
    Y = x[:]
    test_series = []
    if (alpha == None or beta == None or gamma == None or delta == None):
        boundaries = [(0, 1), (0, 1), (0, 1), (0, 1)]
        train_series = Y[:-m2 * 1]
        test_series = Y[-m2 * 1:]
        Y = train_series
        func = RMSE
        parameters = fmin_l_bfgs_b(func, x0=initial_values_optimization, args=(train_series, (m, m2), test_series),
                                   bounds=boundaries, approx_grad=True, factr=10 ** 3)
        alpha, beta, gamma, delta = parameters[0]
    a = [sum(Y[0:m]) / float(m)]
    b = [(sum(Y[m:2 * m]) - sum(Y[0:m])) / m ** 2]
    s = [Y[i] / a[0] for i in range(m)]
    s2 = [Y[i] / a[0] for i in range(0, m2, m)]
    y = [a[0] + s[0] + s2[0]]

    for i in range(len(Y) + forecast + len(test_series)):
        if i >= len(Y):
            Y.append(a[-1] + b[-1] + s[-m] + s2[-m2])
        a.append(alpha * (Y[i] - s2[i] - s[i]) + (1 - alpha) * (a[i] + b[i]))
        b.append(beta * (a[i + 1] - a[i]) + (1 - beta) * b[i])
        s.append(gamma * (Y[i] - a[i] - s2[i]) + (1 - gamma) * s[i])
        s2.append(delta * (Y[i] - a[i] - s[i]) + (1 - delta) * s2[i])
        y.append(a[i + 1] + b[i + 1] + s[i + 1] + s2[i + 1])

    return Y[-forecast:], (alpha, beta, gamma, delta), y[:-forecast], deque(a), deque(b), deque(s), deque(s2), deque(Y)


def HWTStep(Y, a, b, s, s2, alpha, beta, gamma, delta, m, m2):
    a.append(alpha * (Y - s2[-1] - s[-1]) + (1 - alpha) * (a[-1]))
    b.append(beta * (a[-1] - a[-2]) + (1 - beta) * b[-1])
    s.append(gamma * (Y - a[-1] - s2[-1]) + (1 - gamma) * s[-1])
    s2.append(delta * (Y - a[-1] - s[-1]) + (1 - delta) * s2[-1])
    hwt_result = a[-1] + b[-1] + s[-m] + s2[-m2]
    return hwt_result, deque(a), deque(b), deque(s), deque(s2)


def RMSE(params, *args):
    forecast, next_prediction = ParamsEstimation(params, *args)
    test_data = args[2]
    train = args[0]
    rmse_outofsample = sum([(m - n) ** 2 for m, n in zip(test_data, forecast)]) / len(test_data)
    rmse_insample = sum([(m - n) ** 2 for m, n in zip(train, next_prediction)]) / len(train)
    return rmse_insample + rmse_outofsample


def ParamsEstimation(params, *args):
    train = args[0][:]
    m = args[1]
    test_data = args[2]
    alpha, beta, gamma, delta = params
    forecast, params, next_prediction, _, _, _, _, _ = HWT(train, m[0], m[1], len(test_data), alpha=alpha, beta=beta,
                                                           gamma=gamma, delta=delta)

    return forecast, next_prediction


if __name__ == "__main__":
    values = list(xrange(30))
    # print values
    res = HWT(values, 2, 2 * 5, 5, alpha=None, beta=None, gamma=None, delta=None,
              initial_values_optimization=[0.1, 0.5, 0.2, 0.2])

    print res
