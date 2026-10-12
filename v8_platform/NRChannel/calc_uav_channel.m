function [fspl_db, shadowing_db, rician_fading_db] = calc_uav_channel(tx_pos, rx_pos, freq_hz)
    % Static A2A channel: FSPL + log-normal shadowing + Rician fading.
    tx_pos = double(tx_pos);
    rx_pos = double(rx_pos);

    distance_m = max(norm(tx_pos - rx_pos), 1.0);
    speed_of_light = 299792458;
    fspl_db = 20 * log10(4 * pi * distance_m * freq_hz / speed_of_light);

    shadowing_std_db = 2.0;
    shadowing_db = randn() * shadowing_std_db;

    k_factor_db = 10.0;
    k_linear = 10^(k_factor_db / 10);
    h_los = sqrt(k_linear / (k_linear + 1));
    h_scatter = sqrt(1 / (2 * (k_linear + 1))) * (randn() + 1i * randn());
    h = h_los + h_scatter;
    rician_fading_db = 20 * log10(max(abs(h), 1e-12));
end
